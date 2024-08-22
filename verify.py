import hashlib
import random
from typing import List
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

    def retrieve_path_to_root(self, index: int) -> List[Node]:
        """
        Retrieve the path from the leaf node at the given index to the root of the Merkle Tree.
        """
        current_node = self.root
        path = []
        positions = []

        # Calculate positions from base to root
        while index > 0 and len(positions) < self.tree_height() - 1:
            positions.append(index)
            index = (index + 1) // 2

        # print(positions)
        positions.reverse()  # Reverse the list to get positions from root to base
        positions = [i - 1 for i in positions]

        # Iterate through each level to find the correct node at each level
        for pos in positions:
            if pos % 2 == 0:  # Append siblings
                path.append(current_node.right)
                current_node = current_node.left
            else:
                path.append(current_node.left)
                current_node = current_node.right

        return path

    def tree_height(self) -> int:
        """
        Calculate the height of the tree rooted at the given node.
        """
        return self._tree_height(self.root)

    def _tree_height(self, node: Node) -> int:
        """
        Helper function to recursively calculate the height of the tree.
        """
        if node is None:
            return 0
        else:
            # Recursively calculate the height of the left and right subtrees
            left_height = self._tree_height(node.left)
            right_height = self._tree_height(node.right)

            # Return the height of the taller subtree plus 1 for the current node
            return max(left_height, right_height) + 1

    def get_node_at_position(self, position: int) -> Node:
        queue = [self.root]
        current_level = 1
        while queue:
            level_size = len(queue)
            if current_level == self.tree_height():  # Check if it's the base level
                if position <= level_size:  # Ensure position is within bounds
                    # Return the node at the desired position
                    return queue[position - 1]
                else:
                    return None  # Position out of bounds
            for _ in range(level_size):
                node = queue.pop(0)
                if node.left:
                    queue.append(node.left)
                if node.right:
                    queue.append(node.right)
            current_level += 1

    def verify(self, retrieved_values: List[str], NodeVal: Node, idx: int) -> bool:
        """
        Verify the integrity of the Merkle Tree by checking if the retrieved values match the expected hashes.
        """
        retrieved_values.reverse()
        newVal = NodeVal.value
        for val in retrieved_values:
            if idx % 2 == 0:
                newVal = Node.hash(val + newVal)
                idx = idx // 2
            elif idx % 2 != 0:
                newVal = Node.hash(newVal + val)
                idx = (idx + 1) // 2

        if newVal == self.root.value:
            return True

        return False


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

    print("\nMerkle Tree:")
    #  mtree.printTree()
    mtree.visualize_tree()

    # Retrieve the path to the root for node at index 7
    leaf_index = 7
    path_to_root = mtree.retrieve_path_to_root(leaf_index)
    print("\nPath to root for node at index", leaf_index, ":")
    for node in path_to_root:
        print("Node Value:", node.value)

    retrieved_values = [node.value for node in path_to_root]
    result_node = mtree.get_node_at_position(leaf_index)
    # print(result_node, "here")
    Verify = mtree.verify(retrieved_values, result_node, leaf_index)
    if Verify:
        print("\nVerification successful: The data is not modified.")
    else:
        print("\nVerification failed. The data has been tampered.")


if __name__ == "__main__":
    mixmerkletree()
