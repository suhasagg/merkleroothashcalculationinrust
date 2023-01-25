use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::sync::mpsc;
use std::thread;

// LeafNode represents a leaf node in the Merkle tree
struct LeafNode {
    data: Vec<u8>,
    hash: Vec<u8>,
    level: usize,
}

// Node represents a node in the Merkle tree
struct Node {
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
    hash: Vec<u8>,
    level: usize,
}

fn new_leaf_node(data: &[u8]) -> LeafNode {
    let mut sha = Sha256::new();
    sha.input(data);
    let mut hash = vec![0; sha.output_bytes()];
    sha.result(&mut hash);
    LeafNode {
        data: data.to_vec(),
        hash: hash,
        level: 0,
    }
}

fn new_node(left: Node, right: Node) -> Node {
    let mut sha = Sha256::new();
    sha.input(&left.hash);
    sha.input(&right.hash);
    let mut hash = vec![0; sha.output_bytes()];
    sha.result(&mut hash);
    Node {
        left: Some(Box::new(left)),
        right: Some(Box::new(right)),
        hash: hash,
        level: left.level + 1,
    }
}

fn calculate_root(node: &Node) -> Vec<u8> {
    if node.left.is_none() && node.right.is_none() {
        return node.hash.clone();
    }

    let (tx, rx) = mpsc::channel();
    let left = node.left.as_ref().unwrap();
    let right = node.right.as_ref().unwrap();

    thread::spawn(move || {
        let left_root = calculate_root(left);
        tx.send(left_root).unwrap();
    });
    thread::spawn(move || {
        let right_root = calculate_root(right);
        tx.send(right_root).unwrap();
    });

    let left_root = rx.recv().unwrap();
    let right_root = rx.recv().unwrap();

    let mut sha = Sha256::new();
    sha.input(&left_root);
    sha.input(&right_root);
    let mut root = vec![0; sha.output_bytes()];
    sha.result(&mut root);

    root
}
