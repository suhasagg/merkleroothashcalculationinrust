
# merkle root calculation 

Corresponding go version - https://github.com/suhasagg/fastest-merkle-tree-root-hash-calculator

*Calculate the root of the Merkle Tree* (takes care of scalability)

**Supported In Two ways:**

* Send all hashed lists in the old fashioned way.
* Imagine you have 2^64 (18446744073709551616) data needs to be calculated, you might encounter the OOM problem. In order to solve that problem, we maintain a temporary state to store the previous calulation and it will simultaneously change from one step to the next step until it meets our goal.

### Example:
```rust
use rcmerkle::{BetterMerkleTreeSHA256, Hash, MerkleTreeSHA256, SHA256};

let list = [
   "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n",
];
let hashed_list: Vec<SHA256> = list.iter().map(|v| SHA256::hash(v.as_bytes())).collect();

let mut better_merkle = BetterMerkleTreeSHA256::new();

for i in 0..hashed_list.len() {
   let root1 = MerkleTreeSHA256::root(hashed_list[0..i + 1].to_vec());
   let root2 = better_merkle.root(hashed_list[i].clone());
   assert_eq!(root1, root2);
}
```


