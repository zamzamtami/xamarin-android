using System;
using Java.Util;

namespace Java.Util.Concurrent {
        public partial class ConcurrentHashMap {
                public partial class KeySetView {
			bool ICollection.ContainsAll (System.Collections.ICollection collection) {
				foreach (var value in collection) {
					if (Contains (value as Java.Lang.Object)) {
						return true;
					}
				}
				return false;
			}
			bool ICollection.RemoveAll (System.Collections.ICollection c) {
				throw new NotImplementedException ();
			}
			bool ICollection.RetainAll (System.Collections.ICollection c) {
				throw new NotImplementedException ();
			}

			bool ISet.ContainsAll (System.Collections.ICollection collection) {
				throw new NotImplementedException ();
			}
			bool ISet.RemoveAll (System.Collections.ICollection c) {
				throw new NotImplementedException ();
			}
			bool ISet.RetainAll (System.Collections.ICollection c) {
				throw new NotImplementedException ();
			}
		}
	}
}
