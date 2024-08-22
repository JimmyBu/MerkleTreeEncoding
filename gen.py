import hashlib
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.backends import default_backend


class Node:
    def __init__(self, ID: int, left, right, value: str, is_copied=False) -> None:
        self.ID: int = ID
        self.left: Node = left
        self.right: Node = right
        self.value = value
        self.is_copied = is_copied

    @staticmethod
    def hash(val: str) -> str:
        return hashlib.sha3_224(val.encode('utf-8')).hexdigest()

    def __str__(self):
        return str(self.value)

    def copy(self):
        return Node(self.ID, self.left, self.right, self.value, True)


class MerkleTree:
    def __init__(self, d: str, PRNG_numbers: list) -> None:
        self.d = d
        self.PRNG_numbers = PRNG_numbers
        self.__buildTree()

    @staticmethod
    def generate_random_data(length):
        random_data = ''.join(str(random.randint(0, 1)) for _ in range(length))
        return random_data

    @staticmethod
    def generate_PRNG_numbers(n, seed):
        PRNG_numbers = []
        if isinstance(seed, str):
            seed = seed.encode()
        for i in range(n):
            seed = hashlib.sha3_224(seed).digest()
            prng_number_hex = seed.hex()
            prng_number_str = prng_number_hex.zfill(68)  # Zero-pad to ensure consistent length
            PRNG_numbers.append(prng_number_str)
            # print(f"PRNG number {i + 1}: {prng_number_str}")
            # print(f"Length of PRNG number: {len(prng_number_str)}")
        return PRNG_numbers

    def generate_xi(self, IDi, d, si):
        xi = str(IDi) + d + str(si)
        return xi

    def __buildTree(self) -> None:
        leaves = []
        for i, si in enumerate(self.PRNG_numbers):
            IDi = i + 900
            xi = self.generate_xi(IDi, self.d, si)
            leaves.append(Node(IDi, None, None, xi))  # Base level nodes are not hashed

        self.root = self.__buildTreeRec(leaves)

    def __buildTreeRec(self, nodes) -> Node:
        if len(nodes) == 1:
            return nodes[0]

        half = len(nodes) // 2
        left = self.__buildTreeRec(nodes[:half])
        right = self.__buildTreeRec(nodes[half:])
        # print("left: ", left, "right: ", right)
        value = Node.hash(left.value + right.value)  # Concatenation of values
        return Node(left.ID, left, right, value)

    def printTree(self) -> None:
        self.__printTreeRec(self.root)

    def __printTreeRec(self, node: Node) -> None:
        if node is not None:
            if node.left is not None:
                print("Left:", node.left)
                print("Right:", node.right)
            else:
                print("Input")

            if node.is_copied:
                print('(Padding)')
            print("ID:", node.ID)
            print("Value:", node.value)
            print("")
            self.__printTreeRec(node.left)
            self.__printTreeRec(node.right)

    def visualize_tree(self) -> None:
        if not self.root:
            print("Tree is empty.")
            return

        queue = [(self.root, 0)]
        current_level = 0
        while queue:
            node, level = queue.pop(0)
            if level > current_level:
                print("\nLevel", level)
                current_level = level
            print("Node Value:", node.value, end=" | ")
            if node.left:
                queue.append((node.left, level + 1))
            if node.right:
                queue.append((node.right, level + 1))
        print("\n")


def mixmerkletree():
    d = MerkleTree.generate_random_data(1500)
    seed = b'\xff\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'  # Initial seed for PRNG
    PRNG_numbers = MerkleTree.generate_PRNG_numbers(32, seed)
    mtree = MerkleTree(d, PRNG_numbers)

    # DSA
    private_key = dsa.generate_private_key(
        key_size=1024,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    root_value_bytes = bytes.fromhex(mtree.root.value)
    root_hash = hashlib.sha3_224(root_value_bytes).digest()
    signature = private_key.sign(root_hash, hashes.SHA3_224())

    print("\nRoot Hash:", mtree.root.value)
    print("\nRoot DSA:", signature)

    # verify DSA
    try:
        public_key.verify(signature, root_hash, hashes.SHA3_224())
        print("Signature verification successful: The signature is valid.")
    except:
        print("Signature verification failed: The signature is invalid.")

    # print("\nRoot Hash:", mtree.root.value)
    print("\nMerkle Tree:")
    # mtree.printTree()
    mtree.visualize_tree()


if __name__ == "__main__":
    mixmerkletree()
