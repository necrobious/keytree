KeyTree
-------

You probably shouldnt use this library. 

A derived key hierarchy, suitable for encrypting, signing, and verifying data. 
The KeyTree consists of one or more nodes, starting with the root node.
Trust is anchored in the root node.
All other node keys in the hierarchy are derived from the root node's key using a key derivation function along with a derivation-context.

KeyTree library defines:
 - 2 byte static identifier, present on all format versions.
 - 2 byte (u16) indecating the format version number, present on all format versions.
 - a version specific keytree record.

See version specifications under `src` for more detail about a specific verion. 

Versions exist in isolation of each other.
Once comitted, a version should not change, but rather a new version be added.
This means multiple versions will likely exist at the same time.

