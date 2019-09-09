#include <host-config.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <ctype.h>
#include <libgen.h>
#include <errno.h>

#include <mono/metadata/assembly.h>
#include <mono/metadata/image.h>
#include <mono/metadata/mono-config.h>

#include "java-interop-util.h"

#include "monodroid.h"
#include "util.hh"
#include "embedded-assemblies.hh"
#include "globals.hh"
#include "monodroid-glue.h"
#include "xamarin-app.h"
#include "cpp-util.hh"

namespace xamarin::android::internal {
#if defined (DEBUG) || !defined (ANDROID)
	struct TypeMappingInfo {
		char                     *source_apk;
		char                     *source_entry;
		int                       num_entries;
		int                       entry_length;
		int                       value_offset;
		const   char             *mapping;
		TypeMappingInfo          *next;
	};
#endif // DEBUG || !ANDROID
	enum class FileType : uint8_t
	{
		Unknown,
		JavaToManagedTypeMap,
		ManagedToJavaTypeMap,
		DebugInfo,
		Config,
		Assembly,
	};

	struct XamarinBundledAssembly
	{
		XamarinBundledAssembly () = default;

		const char *name;
		const char *apk_name;
		int         apk_fd;
		FileType    type;
		off_t       data_offset;
		size_t      data_size;
		size_t      mmap_size;
		void       *mmap_area;
		void       *mmap_file_data;
	};

	// Amount of RAM that is allowed to be left unused ("wasted") in the `bundled_assemblies`
	// array after all the APK assemblies are loaded. This is to avoid unnecessary `realloc`
	// calls in order to save time.
	static constexpr size_t BUNDLED_ASSEMBLIES_EXCESS_ITEMS_LIMIT = 256 * sizeof(XamarinBundledAssembly);
}

using namespace xamarin::android;
using namespace xamarin::android::internal;

const char *EmbeddedAssemblies::suffixes[] = {
	"",
	".dll",
	".exe",
};

EmbeddedAssemblies::EmbeddedAssemblies ()
	: system_page_size (monodroid_getpagesize())
{}

void EmbeddedAssemblies::set_assemblies_prefix (const char *prefix)
{
	if (assemblies_prefix_override != nullptr)
		delete[] assemblies_prefix_override;
	assemblies_prefix_override = prefix != nullptr ? utils.strdup_new (prefix) : nullptr;
}

template<typename T>
T
EmbeddedAssemblies::get_mmap_file_data (XamarinBundledAssembly& xba)
{
	if (xba.mmap_area == nullptr)
		mmap_apk_file (xba);
	return static_cast<T>(xba.mmap_file_data);
}

inline void
EmbeddedAssemblies::load_assembly_debug_info_from_bundles (const char *aname)
{
	if (!register_debug_symbols || !bundled_assemblies_have_debug_info || aname == nullptr)
		return;

	size_t aname_len = strlen (aname);
	for (size_t i = 0; i < bundled_assemblies_count; i++) {
		XamarinBundledAssembly &entry = bundled_assemblies[i];
		if (entry.type != FileType::DebugInfo)
			continue;

		// We know the entry has one of the debug info extensions, so we can take this shortcut to
		// avoid having to allocate memory and use string comparison in order to find a match for
		// the `aname` assembly
		if (strncmp (entry.name, aname, aname_len) != 0)
			continue;

		size_t ext_len = strlen (entry.name) - aname_len;
		if (ext_len != 4 || ext_len != 8) { // 'Assembly.pdb' || 'Assembly.{exe,dll}.mdb'
			continue;
		}

		mono_register_symfile_for_assembly (aname, get_mmap_file_data<const mono_byte*> (entry), static_cast<int> (entry.data_size));
	}
}

inline void
EmbeddedAssemblies::load_assembly_config_from_bundles (const char *aname)
{
	static constexpr size_t config_ext_len = sizeof(config_ext) - 1;

	if (!bundled_assemblies_have_configs || aname == nullptr)
		return;

	size_t aname_len = strlen (aname);
	for (size_t i = 0; i < bundled_assemblies_count; i++) {
		XamarinBundledAssembly &entry = bundled_assemblies[i];
		if (entry.type != FileType::Config)
			continue;

		// We know the entry has the `.{dll,exe}.config` extension, so we can take this shortcut to
		// avoid having to allocate memory and use string comparison in order to find a match for
		// the `aname` assembly
		if (strncmp (entry.name, aname, aname_len) != 0 ||
		    strlen (entry.name) - aname_len != config_ext_len) {
			continue;
		}

		mono_register_config_for_assembly (aname, get_mmap_file_data <const char*>(entry));
		break;
	}
}

MonoAssembly*
EmbeddedAssemblies::open_from_bundles (MonoAssemblyName* aname, bool ref_only)
{
	const char *culture = mono_assembly_name_get_culture (aname);
	const char *asmname = mono_assembly_name_get_name (aname);

	size_t name_len = culture == nullptr ? 0 : strlen (culture) + 1;
	name_len += sizeof (".exe");
	name_len += strlen (asmname);

	size_t alloc_size = ADD_WITH_OVERFLOW_CHECK (size_t, name_len, 1);
	char *name = new char [alloc_size];
	name [0] = '\0';

	if (culture != nullptr && *culture != '\0') {
		strcat (name, culture);
		strcat (name, "/");
	}
	strcat (name, asmname);
	char *ename = name + strlen (name);

	MonoAssembly *a = nullptr;
	for (size_t si = 0; si < sizeof (suffixes)/sizeof (suffixes [0]) && a == nullptr; ++si) {
		*ename = '\0';
		strcat (name, suffixes [si]);

		log_info (LOG_ASSEMBLY, "open_from_bundles: looking for bundled name: '%s'", name);

		for (size_t i = 0; i < bundled_assemblies_count; i++) {
			XamarinBundledAssembly &assembly = bundled_assemblies[i];

			if (assembly.type != FileType::Assembly || strcmp (assembly.name, name) != 0)
				continue;

			MonoImage *image = mono_image_open_from_data_with_name (get_mmap_file_data<char*>(assembly), static_cast<uint32_t>(assembly.data_size), 0, nullptr, ref_only, name);
			if (image == nullptr)
				break;

			MonoImageOpenStatus status;
			a = mono_assembly_load_from_full (image, name, &status, ref_only);
			if (a == nullptr) {
				mono_image_close (image);
				break;
			}

			load_assembly_config_from_bundles (assembly.name);
			if (!ref_only)
				load_assembly_debug_info_from_bundles (asmname);

			mono_config_for_assembly (image);
			break;
		}
	}
	delete[] name;

	if (XA_UNLIKELY (utils.should_log (LOG_ASSEMBLY) && a != nullptr)) {
		log_info_nocheck (LOG_ASSEMBLY, "open_from_bundles: loaded assembly: %p\n", a);
	}
	return a;
}

MonoAssembly*
EmbeddedAssemblies::open_from_bundles_full (MonoAssemblyName *aname, UNUSED_ARG char **assemblies_path, UNUSED_ARG void *user_data)
{
	return embeddedAssemblies.open_from_bundles (aname, false);
}

MonoAssembly*
EmbeddedAssemblies::open_from_bundles_refonly (MonoAssemblyName *aname, UNUSED_ARG char **assemblies_path, UNUSED_ARG void *user_data)
{
	return embeddedAssemblies.open_from_bundles (aname, true);
}

void
EmbeddedAssemblies::install_preload_hooks ()
{
	mono_install_assembly_preload_hook (open_from_bundles_full, nullptr);
	mono_install_assembly_refonly_preload_hook (open_from_bundles_refonly, nullptr);
}

int
EmbeddedAssemblies::TypeMappingInfo_compare_key (const void *a, const void *b)
{
	return strcmp (reinterpret_cast <const char*> (a), reinterpret_cast <const char*> (b));
}

inline const char*
EmbeddedAssemblies::find_entry_in_type_map (const char *name, uint8_t map[], TypeMapHeader& header)
{
	const char *e = reinterpret_cast<const char*> (bsearch (name, map, header.entry_count, header.entry_length, TypeMappingInfo_compare_key ));
	if (e == nullptr)
		return nullptr;
	return e + header.value_offset;
}

inline const char*
EmbeddedAssemblies::typemap_java_to_managed (const char *java)
{
#if defined (DEBUG) || !defined (ANDROID)
	for (TypeMappingInfo *info = java_to_managed_maps; info != nullptr; info = info->next) {
		/* log_warn (LOG_DEFAULT, "# jonp: checking file: %s!%s for type '%s'", info->source_apk, info->source_entry, java); */
		const char *e = reinterpret_cast<const char*> (bsearch (java, info->mapping, static_cast<size_t>(info->num_entries), static_cast<size_t>(info->entry_length), TypeMappingInfo_compare_key));
		if (e == nullptr)
			continue;
		return e + info->value_offset;
	}
#endif
	return find_entry_in_type_map (java, jm_typemap, jm_typemap_header);
}

inline const char*
EmbeddedAssemblies::typemap_managed_to_java (const char *managed)
{
#if defined (DEBUG) || !defined (ANDROID)
	for (TypeMappingInfo *info = managed_to_java_maps; info != nullptr; info = info->next) {
		/* log_warn (LOG_DEFAULT, "# jonp: checking file: %s!%s for type '%s'", info->source_apk, info->source_entry, managed); */
		const char *e = reinterpret_cast <const char*> (bsearch (managed, info->mapping, static_cast<size_t>(info->num_entries), static_cast<size_t>(info->entry_length), TypeMappingInfo_compare_key));
		if (e == nullptr)
			continue;
		return e + info->value_offset;
	}
#endif
	return find_entry_in_type_map (managed, mj_typemap, mj_typemap_header);
}

MONO_API const char *
monodroid_typemap_java_to_managed (const char *java)
{
	return embeddedAssemblies.typemap_java_to_managed (java);
}

MONO_API const char *
monodroid_typemap_managed_to_java (const char *managed)
{
	return embeddedAssemblies.typemap_managed_to_java (managed);
}

#if defined (DEBUG) || !defined (ANDROID)
void
EmbeddedAssemblies::extract_int (const char **header, const char *source_apk, const char *source_entry, const char *key_name, int *value)
{
	int    read              = 0;
	int    consumed          = 0;
	size_t key_name_len      = 0;
	char   scanf_format [20] = { 0, };

	if (header == nullptr || *header == nullptr)
		return;

	key_name_len    = strlen (key_name);
	if (key_name_len >= (sizeof (scanf_format) - sizeof ("=%d%n"))) {
		*header = nullptr;
		return;
	}

	snprintf (scanf_format, sizeof (scanf_format), "%s=%%d%%n", key_name);

	read = sscanf (*header, scanf_format, value, &consumed);
	if (read != 1) {
		log_warn (LOG_DEFAULT, "Could not read header '%s' value from '%s!%s': read %i elements, expected 1 element. Contents: '%s'",
				key_name, source_apk, source_entry, read, *header);
		*header = nullptr;
		return;
	}
	*header = *header + consumed + 1;
}

bool
EmbeddedAssemblies::add_type_mapping (TypeMappingInfo **info, const char *source_apk, const char *source_entry, const char *addr)
{
	TypeMappingInfo *p        = new TypeMappingInfo (); // calloc (1, sizeof (struct TypeMappingInfo));
	int              version  = 0;
	const char      *data     = addr;

	extract_int (&data, source_apk, source_entry, "version",   &version);
	if (version != 1) {
		delete p;
		log_warn (LOG_DEFAULT, "Unsupported version '%i' within type mapping file '%s!%s'. Ignoring...", version, source_apk, source_entry);
		return false;
	}

	extract_int (&data, source_apk, source_entry, "entry-count",  &p->num_entries);
	extract_int (&data, source_apk, source_entry, "entry-len",    &p->entry_length);
	extract_int (&data, source_apk, source_entry, "value-offset", &p->value_offset);
	p->mapping      = data;

	if ((p->mapping == 0) ||
			(p->num_entries <= 0) ||
			(p->entry_length <= 0) ||
			(p->value_offset >= p->entry_length) ||
			(p->mapping == nullptr)) {
		log_warn (LOG_DEFAULT, "Could not read type mapping file '%s!%s'. Ignoring...", source_apk, source_entry);
		delete p;
		return false;
	}

	p->source_apk   = strdup (source_apk);
	p->source_entry = strdup (source_entry);
	if (*info) {
		(*info)->next = p;
	} else {
		*info = p;
	}
	return true;
}
#endif // DEBUG || !ANDROID

void
EmbeddedAssemblies::mmap_apk_file (XamarinBundledAssembly& xba)
{
	if (xba.mmap_area != nullptr)
		return; // already mapped

	assert (xba.apk_fd >= 0 && "APK file descriptor must be set!");

	auto pageSize       = static_cast<size_t>(system_page_size);
	auto offsetFromPage = static_cast<off_t>(static_cast<size_t>(xba.data_offset) % pageSize);
	off_t offsetPage    = xba.data_offset - offsetFromPage;
	size_t offsetSize   = xba.data_size + static_cast<size_t>(offsetFromPage);

	xba.mmap_area        = mmap (nullptr, offsetSize, PROT_READ, MAP_PRIVATE, xba.apk_fd, offsetPage);

	if (xba.mmap_area == MAP_FAILED) {
		log_fatal (LOG_DEFAULT, "Could not `mmap` apk `%s` entry `%s`: %s", xba.apk_name, xba.name, strerror (errno));
		exit (FATAL_EXIT_CANNOT_FIND_APK);
	}

	xba.mmap_size = offsetSize;
	xba.mmap_file_data = static_cast<void*>(static_cast<uint8_t*>(xba.mmap_area) + offsetFromPage);

	log_info (LOG_ASSEMBLY, "                       mmap_start: %08p  mmap_end: %08p  mmap_len: % 12u  file_start: %08p  file_end: %08p  file_len: % 12u      apk: %s  file: %s",
	          xba.mmap_area, reinterpret_cast<uint8_t*> (xba.mmap_area) + xba.mmap_size, static_cast<uint32_t>(xba.mmap_size),
	          xba.mmap_file_data, reinterpret_cast<int*> (xba.mmap_file_data) + xba.data_size, static_cast<uint32_t> (xba.data_size), xba.apk_name, xba.name);
}

#if defined (DEBUG) || !defined (ANDROID)
void
EmbeddedAssemblies::try_load_typemaps_from_directory (const char *path)
{
	// read the entire typemap file into a string
	// process the string using the add_type_mapping
	char *dir_path = utils.path_combine (path, "typemaps");
	if (dir_path == nullptr || !utils.directory_exists (dir_path)) {
		log_warn (LOG_DEFAULT, "directory does not exist: `%s`", dir_path);
		free (dir_path);
		return;
	}

	monodroid_dir_t *dir;
	if ((dir = utils.monodroid_opendir (dir_path)) == nullptr) {
		log_warn (LOG_DEFAULT, "could not open directory: `%s`", dir_path);
		free (dir_path);
		return;
	}

	monodroid_dirent_t *e;
	while ((e = androidSystem.readdir (dir)) != nullptr) {
#if WINDOWS
		char *file_name = utils.utf16_to_utf8 (e->d_name);
#else   /* def WINDOWS */
		char *file_name = e->d_name;
#endif  /* ndef WINDOWS */
		char *file_path = utils.path_combine (dir_path, file_name);
		if (utils.monodroid_dirent_hasextension (e, ".mj") || utils.monodroid_dirent_hasextension (e, ".jm")) {
			char *val = nullptr;
			size_t len = androidSystem.monodroid_read_file_into_memory (file_path, &val);
			if (len > 0 && val != nullptr) {
				if (utils.monodroid_dirent_hasextension (e, ".mj")) {
					if (!add_type_mapping (&managed_to_java_maps, file_path, override_typemap_entry_name, ((const char*)val)))
						delete[] val;
				} else if (utils.monodroid_dirent_hasextension (e, ".jm")) {
					if (!add_type_mapping (&java_to_managed_maps, file_path, override_typemap_entry_name, ((const char*)val)))
						delete[] val;
				}
			}
		}
	}
	utils.monodroid_closedir (dir);
	free (dir_path);
	return;
}
#endif

size_t
EmbeddedAssemblies::register_from (const char *apk_file, size_t total_apk_count, monodroid_should_register should_register)
{
	int fd;

	if ((fd = open (apk_file, O_RDONLY)) < 0) {
		log_error (LOG_DEFAULT, "ERROR: Unable to load application package %s. %s", apk_file, strerror (errno));
		return bundled_assemblies_count;
	}

	size_t prev  = bundled_assemblies_count;
	if (!zip_load_entries (fd, apk_file, total_apk_count, should_register)) {
		close (fd);
		return bundled_assemblies_count;
	}

	log_info (LOG_ASSEMBLY, "Package '%s' contains %i assemblies", apk_file, bundled_assemblies_count - prev);

	return bundled_assemblies_count;
}

inline void
EmbeddedAssemblies::resize_bundled_assemblies (size_t new_size)
{
	assert (new_size >= bundled_assemblies_count && "Shrinking bundled_assemblies would lose data");

	auto new_array = new XamarinBundledAssembly[new_size];

	// We can safely do this because XamarinBundledAssembly is POD (Plain Old Data) and we don't
	// need to worry about copy constructors and destructors
	if (bundled_assemblies_count > 0) {
		memcpy (new_array, bundled_assemblies, bundled_assemblies_count * sizeof(XamarinBundledAssembly));
	}

	delete[] bundled_assemblies;
	bundled_assemblies = new_array;
	bundled_assemblies_size = new_size;
}

void
EmbeddedAssemblies::bundled_assemblies_cleanup ()
{
	if (bundled_assemblies_size - bundled_assemblies_count <= BUNDLED_ASSEMBLIES_EXCESS_ITEMS_LIMIT) {
		return;
	}

	resize_bundled_assemblies (bundled_assemblies_count);
}

bool
EmbeddedAssemblies::zip_load_entries (int fd, const char *apk_name, size_t total_apk_count, monodroid_should_register should_register)
{
	uint32_t cd_offset;
	uint32_t cd_size;
	uint16_t cd_entries;

	if (!zip_read_cd_info (fd, cd_offset, cd_size, cd_entries)) {
		log_fatal (LOG_DEFAULT,  "Failed to read the EOCD record from APK file %s", apk_name);
		return false;
	}
#ifdef DEBUG
	log_info (LOG_DEFAULT, "Central directory offset: %u", cd_offset);
	log_info (LOG_DEFAULT, "Central directory size: %u", cd_size);
	log_info (LOG_DEFAULT, "Central directory entries: %u", cd_entries);
#endif
	off_t result = ::lseek (fd, static_cast<off_t>(cd_offset), SEEK_SET);
	if (result < 0) {
		log_fatal (LOG_DEFAULT, "Failed to seek to central directory position in the APK file %s", apk_name);
		return false;
	}

	if (bundled_assemblies == nullptr) {
		bundled_assemblies_count = 0;
		bundled_assemblies_size = MULTIPLY_WITH_OVERFLOW_CHECK (size_t, cd_entries, total_apk_count);
		bundled_assemblies = new XamarinBundledAssembly[bundled_assemblies_size];
	} else if (bundled_assemblies_size - bundled_assemblies_count <= cd_entries) {
		resize_bundled_assemblies (ADD_WITH_OVERFLOW_CHECK (size_t, bundled_assemblies_size, cd_entries << 1));
	}

	// C++17 allows template parameter type inference, but alas, Apple's antiquated compiler does
	// not support this particular part of the spec...
	simple_pointer_guard<uint8_t[]>  buf (new uint8_t[cd_size]);
	const char           *apk        = nullptr;
	const char           *prefix     = get_assemblies_prefix ();
	size_t                prefix_len = strlen (prefix);
	size_t                buf_offset = 0;
	uint16_t              compression_method;
	uint32_t              local_header_offset;
	uint32_t              data_offset;
	uint32_t              file_size;
	char                 *entry_name;
	char                 *file_name;

	ssize_t nread = read (fd, buf.get (), cd_size);
	if (static_cast<size_t>(nread) != cd_size) {
		log_fatal (LOG_DEFAULT, "Failed to read Central Directory from the APK archive %s", apk_name);
		return false;
	}

	for (size_t i = 0; i < cd_entries; i++) {
		bool result = zip_read_entry_info (buf.get (), cd_size, buf_offset, compression_method, local_header_offset, file_size, entry_name);
		simple_pointer_guard<char> entry_name_guard = entry_name;
		file_name = entry_name_guard.get ();

		if (!result) {
			log_fatal (LOG_DEFAULT, "Failed to read Central Directory info for entry %u in APK file %s", i, apk_name);
			return false;
		}

		if (!zip_adjust_data_offset (fd, local_header_offset, data_offset)) {
			log_fatal (LOG_DEFAULT, "Failed to adjust data start offset for entry %u in APK file %s", i, apk_name);
			return false;
		}

		if (compression_method != 0)
			continue;

		if (strncmp (prefix, file_name, strlen (prefix)) != 0)
			continue;

		// assemblies must be 4-byte aligned, or Bad Things happen
		if ((data_offset & 0x3) != 0) {
			log_fatal (LOG_ASSEMBLY, "Assembly '%s' is located at bad offset %lu within the .apk\n", file_name, data_offset);
			log_fatal (LOG_ASSEMBLY, "You MUST run `zipalign` on %s\n", strrchr (apk_name, '/') + 1);
			exit (FATAL_EXIT_MISSING_ZIPALIGN);
		}

		FileType type = FileType::Unknown;
		bool entry_is_overridden = !should_register (strrchr (file_name, '/') + 1);

#if defined (DEBUG)
		bool mmap_now = false;

		if (utils.ends_with (file_name, ".jm")) {
			mmap_now = true;
			type = FileType::JavaToManagedTypeMap;
		} else if (utils.ends_with (file_name, ".mj")) {
			mmap_now = true;
			type = FileType::ManagedToJavaTypeMap;
		} else
#endif
		if (utils.ends_with (file_name, mdb_ext) || utils.ends_with (file_name, pdb_ext)) {
			if (!register_debug_symbols || entry_is_overridden) {
				continue;
			}

			type = FileType::DebugInfo;
			bundled_assemblies_have_debug_info = true;
		} else if (utils.ends_with (file_name, config_ext)) {
			type = FileType::Config;
			bundled_assemblies_have_configs = true;
		} else if (utils.ends_with (file_name, ".dll") || utils.ends_with (file_name, ".exe")) {
			type = FileType::Assembly;
		} else
			continue;

		if (entry_is_overridden)
			continue;

		if (apk == nullptr)
			apk = utils.strdup_new (apk_name);

		XamarinBundledAssembly &assembly = bundled_assemblies [bundled_assemblies_count++];
		assembly.name           = utils.strdup_new (strstr (file_name, prefix) + prefix_len);
		assembly.apk_name       = apk;
		assembly.apk_fd         = fd;
		assembly.type           = type;
		assembly.data_offset    = static_cast<off_t>(data_offset);
		assembly.data_size      = file_size;
#if DEBUG
		if (!mmap_now) {
#endif
			assembly.mmap_size      = 0;
			assembly.mmap_area      = nullptr;
			assembly.mmap_file_data = nullptr;
#ifdef DEBUG
			continue;
		}

		switch (type) {
			case FileType::JavaToManagedTypeMap:
				mmap_apk_file (assembly);
				add_type_mapping (&java_to_managed_maps, assembly.apk_name, file_name, static_cast<const char*> (assembly.mmap_file_data));
				bundled_assemblies_count--; // Save on space in `bundled_assemblies` and a bit of
											// time when traversing the array during on-demand loads
				break;

			case FileType::ManagedToJavaTypeMap:
				mmap_apk_file (assembly);
				add_type_mapping (&managed_to_java_maps, assembly.apk_name, file_name, static_cast<const char*> (assembly.mmap_file_data));
				bundled_assemblies_count--; // As above
				break;

			default:
				log_fatal (LOG_DEFAULT, "Internal error: unsupported file type %f for immediate mapping", type);
				return false;
		}
#endif
	}

	return true;
}

bool
EmbeddedAssemblies::zip_read_cd_info (int fd, uint32_t& cd_offset, uint32_t& cd_size, uint16_t& cd_entries)
{
	// The simplest case - no file comment
	off_t ret = ::lseek (fd, -ZIP_EOCD_LEN, SEEK_END);
	if (ret < 0) {
		log_fatal (LOG_DEFAULT, "Unable to seek into the APK to find ECOD: %s", std::strerror (errno));
		return false;
	}

	uint8_t eocd[ZIP_EOCD_LEN];
	ssize_t nread = ::read (fd, eocd, static_cast<size_t>(ZIP_EOCD_LEN));
	if (nread < 0 || nread != ZIP_EOCD_LEN) {
		log_fatal (LOG_DEFAULT, "Failed to read EOCD from the APK: %s", std::strerror (errno));
		return false;
	}

	size_t index = 0; // signature
	uint8_t signature[4];

	if (!zip_read_field (eocd, ZIP_EOCD_LEN, index, signature)) {
		log_fatal (LOG_DEFAULT, "Failed to read EOCD signature");
		return false;
	}

	if (memcmp (signature, ZIP_EOCD_MAGIC, sizeof(signature)) == 0) {
		return zip_extract_cd_info (eocd, ZIP_EOCD_LEN, cd_offset, cd_size, cd_entries);
	}

	// Most probably a ZIP with comment
	size_t alloc_size = 65535 + ZIP_EOCD_LEN; // 64k is the biggest comment size allowed
	ret = lseek (fd, static_cast<off_t>(-alloc_size), SEEK_END);
	if (ret < 0) {
		log_fatal (LOG_DEFAULT, "Unable to seek into the file to find ECOD before APK comment: ", std::strerror (errno));
		return false;
	}

	auto buf = new uint8_t[alloc_size];
	nread = ::read (fd, buf, alloc_size);

	if (nread < 0 || static_cast<size_t>(nread) != alloc_size) {
		log_fatal (LOG_DEFAULT, "Failed to read EOCD and comment from the APK: ", std::strerror (errno));
		return false;
	}

	// We scan from the end to save time
	bool found = false;
	for (ssize_t i = static_cast<ssize_t>(alloc_size - (ZIP_EOCD_LEN + 2)); i >= 0; i--) {
		if (memcmp (buf + i, ZIP_EOCD_MAGIC, sizeof(ZIP_EOCD_MAGIC)) != 0)
			continue;

		found = true;
		memcpy (eocd, buf + i, ZIP_EOCD_LEN);
		break;
	}

	delete[] buf;
	if (!found) {
		log_fatal (LOG_DEFAULT, "Unable to find EOCD in the APK (with comment)");
		return false;
	}

	return zip_extract_cd_info (eocd, ZIP_EOCD_LEN, cd_offset, cd_size, cd_entries);
}

bool
EmbeddedAssemblies::zip_adjust_data_offset (int fd, size_t local_header_offset, uint32_t &data_start_offset)
{
	static constexpr size_t LH_FILE_NAME_LENGTH_OFFSET   = 26;
	static constexpr size_t LH_EXTRA_LENGTH_OFFSET       = 28;

	off_t result = ::lseek (fd, static_cast<off_t>(local_header_offset), SEEK_SET);
	if (result < 0) {
		log_fatal (LOG_DEFAULT, "Failed to seek to archive entry local header at offset %u", local_header_offset);
		return false;
	}

	uint8_t local_header[ZIP_LOCAL_LEN];
	uint8_t signature[4];

	ssize_t nread = ::read (fd, local_header, static_cast<size_t>(ZIP_LOCAL_LEN));
	if (nread < 0 || nread != ZIP_LOCAL_LEN) {
		log_fatal (LOG_DEFAULT, "Failed to read local header at offset %u: ", local_header_offset, std::strerror (errno));
		return false;
	}

	size_t index = 0;
	if (!zip_read_field (local_header, ZIP_LOCAL_LEN, index, signature)) {
		log_fatal (LOG_DEFAULT, "Failed to read Local Header entry signature at offset %u", local_header_offset);
		return false;
	}

	if (memcmp (signature, ZIP_LOCAL_MAGIC, sizeof(signature)) != 0) {
		log_fatal (LOG_DEFAULT, "Invalid Local Header entry signature at offset %u", local_header_offset);
		return false;
	}

	uint16_t file_name_length;
	index = LH_FILE_NAME_LENGTH_OFFSET;
	if (!zip_read_field (local_header, ZIP_LOCAL_LEN, index, file_name_length)) {
		log_fatal (LOG_DEFAULT, "Failed to read Local Header 'file name length' field at offset %u", (local_header_offset + index));
		return false;
	}

	uint16_t extra_field_length;
	index = LH_EXTRA_LENGTH_OFFSET;
	if (!zip_read_field (local_header, ZIP_LOCAL_LEN, index, extra_field_length)) {
		log_fatal (LOG_DEFAULT, "Failed to read Local Header 'extra field length' field at offset %u", (local_header_offset + index));
		return false;
	}

	data_start_offset = static_cast<uint32_t>(local_header_offset) + file_name_length + extra_field_length + ZIP_LOCAL_LEN;

	return true;
}

bool
EmbeddedAssemblies::zip_extract_cd_info (uint8_t* buf, size_t buf_len, uint32_t& cd_offset, uint32_t& cd_size, uint16_t& cd_entries)
{
	static constexpr size_t EOCD_TOTAL_ENTRIES_OFFSET = 10;
	static constexpr size_t EOCD_CD_SIZE_OFFSET       = 12;
	static constexpr size_t EOCD_CD_START_OFFSET      = 16;

	if (buf_len < ZIP_EOCD_LEN) {
		log_fatal (LOG_DEFAULT, "Buffer to short for EOCD");
		return false;
	}

	if (!zip_read_field (buf, buf_len, EOCD_TOTAL_ENTRIES_OFFSET, cd_entries)) {
		log_fatal (LOG_DEFAULT, "Failed to read EOCD 'total number of entries' field");
		return false;
	}

	if (!zip_read_field (buf, buf_len, EOCD_CD_START_OFFSET, cd_offset)) {
		log_fatal (LOG_DEFAULT, "Failed to read EOCD 'central directory size' field");
		return false;
	}

	if (!zip_read_field (buf, buf_len, EOCD_CD_SIZE_OFFSET, cd_size)) {
		log_fatal (LOG_DEFAULT, "Failed to read EOCD 'central directory offset' field");
		return false;
	}

	return true;
}

bool
EmbeddedAssemblies::zip_ensure_valid_params (uint8_t* buf, size_t buf_len, size_t index, size_t to_read)
{
	assert (buf != nullptr);
	if (index + to_read > buf_len) {
		log_fatal (LOG_DEFAULT, "Buffer too short to read %u bytes of data", to_read);
		return false;
	}

	return true;
}

bool
EmbeddedAssemblies::zip_read_field (uint8_t* buf, size_t buf_len, size_t index, uint16_t& u)
{
	if (!zip_ensure_valid_params (buf, buf_len, index, sizeof (u)))
		return false;

	u = static_cast<uint16_t> (buf [index + 1] << 8) |
		static_cast<uint16_t> (buf [index]);

	return true;
}

bool
EmbeddedAssemblies::zip_read_field (uint8_t* buf, size_t buf_len, size_t index, uint32_t& u)
{
	if (!zip_ensure_valid_params (buf, buf_len, index, sizeof (u)))
		return false;

	u = (static_cast<uint32_t> (buf [index + 3]) << 24) |
		(static_cast<uint32_t> (buf [index + 2]) << 16) |
		(static_cast<uint32_t> (buf [index + 1]) << 8)  |
		(static_cast<uint32_t> (buf [index + 0]));

	return true;
}

bool
EmbeddedAssemblies::zip_read_field (uint8_t* buf, size_t buf_len, size_t index, uint8_t (&sig)[4])
{
	static constexpr size_t sig_size = sizeof(sig);

	if (!zip_ensure_valid_params (buf, buf_len, index, sig_size))
		return false;

	memcpy (sig, buf + index, sig_size);
	return true;
}

bool
EmbeddedAssemblies::zip_read_field (uint8_t* buf, size_t buf_len, size_t index, size_t count, char*& characters)
{
	if (!zip_ensure_valid_params (buf, buf_len, index, count))
		return false;

	characters = new char[count + 1];
	memcpy (characters, buf + index, count);
	characters [count] = '\0';

	return true;
}

bool
EmbeddedAssemblies::zip_read_entry_info (uint8_t* buf, size_t buf_len, size_t& buf_offset, uint16_t& compression_method, uint32_t& local_header_offset, uint32_t& file_size, char*& file_name)
{
	static constexpr size_t CD_COMPRESSION_METHOD_OFFSET = 10;
	static constexpr size_t CD_UNCOMPRESSED_SIZE_OFFSET  = 24;
	static constexpr size_t CD_FILENAME_LENGTH_OFFSET    = 28;
	static constexpr size_t CD_EXTRA_LENGTH_OFFSET       = 30;
	static constexpr size_t CD_COMMENT_LENGTH_OFFSET     = 32;
	static constexpr size_t CD_LOCAL_HEADER_POS_OFFSET   = 42;

	size_t index = buf_offset;
	if (!zip_ensure_valid_params (buf, buf_len, index, ZIP_CENTRAL_LEN))
		return false;

	uint8_t signature[4];
	if (!zip_read_field (buf, buf_len, index, signature)) {
		log_fatal (LOG_DEFAULT, "Failed to read Central Directory entry signature");
		return false;
	}

	if (memcmp (signature, ZIP_CENTRAL_MAGIC, sizeof(signature)) != 0) {
		log_fatal (LOG_DEFAULT, "Invalid Central Directory entry signature");
		return false;
	}

	index = buf_offset + CD_COMPRESSION_METHOD_OFFSET;
	if (!zip_read_field (buf, buf_len, index, compression_method)) {
		log_fatal (LOG_DEFAULT, "Failed to read Central Directory entry 'compression method' field");
		return false;
	}

	index = buf_offset + CD_UNCOMPRESSED_SIZE_OFFSET;;
	if (!zip_read_field (buf, buf_len, index, file_size)) {
		log_fatal (LOG_DEFAULT, "Failed to read Central Directory entry 'uncompressed size' field");
		return false;
	}

	uint16_t file_name_length;
	index = buf_offset + CD_FILENAME_LENGTH_OFFSET;
	if (!zip_read_field (buf, buf_len, index, file_name_length)) {
		log_fatal (LOG_DEFAULT, "Failed to read Central Directory entry 'file name length' field");
		return false;
	}

	uint16_t extra_field_length;
	index = buf_offset + CD_EXTRA_LENGTH_OFFSET;
	if (!zip_read_field (buf, buf_len, index, extra_field_length)) {
		log_fatal (LOG_DEFAULT, "Failed to read Central Directory entry 'extra field length' field");
		return false;
	}

	uint16_t comment_length;
	index = buf_offset + CD_COMMENT_LENGTH_OFFSET;
	if (!zip_read_field (buf, buf_len, index, comment_length)) {
		log_fatal (LOG_DEFAULT, "Failed to read Central Directory entry 'file comment length' field");
		return false;
	}

	index = buf_offset + CD_LOCAL_HEADER_POS_OFFSET;
	if (!zip_read_field (buf, buf_len, index, local_header_offset)) {
		log_fatal (LOG_DEFAULT, "Failed to read Central Directory entry 'relative offset of local header' field");
		return false;
	}
	index += sizeof(local_header_offset);

	if (file_name_length == 0) {
		file_name = new char[1];
		file_name[0] = '\0';
	} else if (!zip_read_field (buf, buf_len, index, file_name_length, file_name)) {
		log_fatal (LOG_DEFAULT, "Failed to read Central Directory entry 'file name' field");
		return false;
	}

	buf_offset += ZIP_CENTRAL_LEN + file_name_length + extra_field_length + comment_length;
	return true;
}

MONO_API int monodroid_embedded_assemblies_set_assemblies_prefix (const char *prefix)
{
	embeddedAssemblies.set_assemblies_prefix (prefix);
	return 0;
}
