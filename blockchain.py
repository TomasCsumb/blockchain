import hashlib
import time

class Block: 
    def __init__(self, data: str, prevHash: str, timeStamp: int, prefix: int) -> None:
        self.__hash: str = None
        self.__prevHash: str = prevHash
        self.__shadowPrevHash = prevHash
        if prevHash is None:
            self.__shadowPrevHash = "" # accounting for genesis block
        self.__data: str = data
        self.__timeStamp: int = timeStamp #long deprecated 
        self.__pow: int = 0
        self.__prefix: int = prefix
        self.__mask = (0xFFFF) << (16 - prefix)
        self.__two_bytes_mask = 0xFFFF
        if prefix > 16:
            raise ValueError('Prefix size greater than 16 bits is not supported.')
        self.mineBlock()
    #end init

    @property
    def hash(self):
        return self.__hash

    @hash.setter
    def hash(self, value):
        self.__hash = value

    @property
    def prevHash(self):
        return self.__prevHash

    @prevHash.setter
    def prevHash(self, value):
        if value is None:
            self.__shadowPrevHash = ""
        self.__prevHash = value

    @property
    def data(self):
        return self.__data

    @data.setter
    def data(self, value):
        self.__data = value

    @property
    def timeStamp(self):
        return self.__timeStamp

    @timeStamp.setter
    def timeStamp(self, value):
        self.__timeStamp = value

    @property
    def pow(self):
        return self.__pow

    @pow.setter
    def pow(self, value):
        self.__pow = value

    @property
    def prefix(self):
        return self.__prefix

    @prefix.setter
    def prefix(self, value):
        self.__prefix = value


    def generateBlockHash(self) -> str:
        concat_block: str = str(self.__pow) + str(self.__shadowPrevHash) + self.__data + str(self.__timeStamp)
        sha256_hash = hashlib.sha256()

        # Update the hash object with the input string encoded as bytes
        sha256_hash.update(concat_block.encode('utf-8'))

        # Get the hash as a hex representation of a byte buffer
        candidate_hash = sha256_hash.hexdigest()
        return candidate_hash
    #end generateBlockHash() 


    def mineBlock(self):
        while self.__hash is None:
            hash_candidate = self.generateBlockHash()
            if (self.check_leading_zeros(hash_candidate)):
                self.__hash = hash_candidate
            else:
                self.__pow += 1
        print(f'POW: {self.__pow}')
        return
    #end mine_block
        

    def check_leading_zeros(self, candidate_hash: str) -> bool:
        bytes_hash = bytes.fromhex(candidate_hash)

        # Extract the bytes from the buffer
        bytes_to_check = bytes_hash[0:2]  # Take the first two bytes (up to 16 bits)

        bytes_as_int = int.from_bytes(bytes_to_check, byteorder='big') # & self.__two_bytes_mask

        # Perform a bitwise AND operation to check if the first n bits are zero
        result_as_int = bytes_as_int & self.__mask

        mask = self.__mask

        if result_as_int == 0:
            print(f'bytes_as_int: {bytes_as_int:x}, result_as_int: {result_as_int:x}, mask: {mask:x}')
            print(' ')

        return result_as_int == 0
    #end check_leading_zeros


    def to_string(self) -> str:
        block_str: str = "data: " + self.data + '\n'
        block_str += "prefix: " + str(self.prefix) + '\n'
        if self.prevHash is None:
            block_str += "prev hash: NULL \n"
        else:
            block_str += "prev hash: " + self.prevHash + '\n'
        block_str += "hash: " + self.hash + '\n'
        return block_str

#end class Block
    
    # Block(data: String, prevHash:  String, timeStamp: long, prefix:int) + generateBlockHash(): String + mineBlock(): String

class BlockChain:
    def __init__(self) -> None:
        self.__blocks: list[Block] = []
        self.__chainSize: int = 0

    #end __init__

    @property
    def blocks(self) -> list[Block]:
        return self.__blocks

    @blocks.setter
    def blocks(self, new_blocks: list[Block]) -> None:
        self.__blocks = new_blocks
        self.__chainSize = len(self.__blocks)

    @property
    def chainSize(self) -> int:
        return self.__chainSize

    @chainSize.setter
    def chainSize(self, new_chain_size: int) -> None:
        self.__chainSize = new_chain_size
     
    
    def addBlock(self, new_block: Block) -> None:
        self.__blocks.append(new_block)
        self.__chainSize = len(self.__blocks)
    #end addBlock


    def __check_hash(self, block: Block) -> bool:
        test_hash = block.generateBlockHash()
        return test_hash == block.hash
    #end check_hash


    def __check_prev_hash(self, prev_block: Block, curr_block: Block) -> bool:
        test_hash = prev_block.generateBlockHash()
        return test_hash == curr_block.prevHash
    #end check_prev_hash


    def __check_pow(self, block: Block) -> bool:
        mask = BlockChain.create_mask(block.prefix)
        bytes_hash = bytes.fromhex(block.hash)

        # Extract the bytes from the buffer
        bytes_to_check = bytes_hash[0:2]  # Take the first two bytes (up to 16 bits)

        bytes_as_int = int.from_bytes(bytes_to_check, byteorder='big') # & self.__two_bytes_mask

        # Perform a bitwise AND operation to check if the first n bits are zero
        result_as_int = bytes_as_int & mask

        if result_as_int == 0:
            print(f'bytes_as_int: {bytes_as_int:x}, result_as_int: {result_as_int:x}, mask: {mask:x}')
            print(' ')

        return result_as_int == 0
    #end check_pow


    @classmethod
    def create_mask(cls, prefix: int) -> int:
        mask = (0xFFFF) << (16 - prefix)
        # two_bytes_mask = 0xFFFF
        if prefix > 16:
            raise ValueError('Prefix size greater than 16 bits is not supported.')
        return mask
    #end create_mask

    
    def to_string(self) -> str:
        blockchain_str: str = "Length of blockchain: " + str(self.chainSize) + '\n'
        for block in self.blocks:
            blockchain_str += block.to_string()
        return blockchain_str
    #end of to_string

    
    """
    • verify() method: this method should go through every block in the blocks and check for  the following: 
    o The stored hash of the block is actually what it computes. 
    o The hash of the previous block stored in the current block is actually the hash of the  previous block, except for the genesis block. 
    o The current block has been mined properly. 
    This method returns true if all blocks in the chain are verified, and returns false otherwise. • toString() method: this method should 
    return a string that contains the size of the chain  and information of every block in the same order as stored in the chain. For each block,
    include  the following information: data, prefix, previous hash’s block, and hash value. You should  consider implementing a toString() method
    in the Block class and use it in this method. You should choose a readable format of the blockchain for the output string. 
    """
    def verify(self) -> bool:
        valid_list: list[int] = []
        invalid_list: list[int] = []
        valid: bool = True

        #check if the chain is empty
        if self.__chainSize == 0:
            return valid
        #check if block zero is the genesis block
        genesis_block = self.__blocks[0]
        valid = valid and (genesis_block).prevHash is None
        #check if the genesis block hash is valid
        valid = valid and self.__check_hash(genesis_block)
        #check if the pow of the genesis block is valid
        valid = valid and self.__check_pow(genesis_block)

        if valid:
            valid_list.append(0)
            print(f'genesis block has been verified')
        else:
            invalid_list.append(0)
            print(f'genesis block verification failed')

        prev_block: Block = genesis_block
        for i in range(1, self.__chainSize):
            curr_block = self.__blocks[i]
            valid = valid and self.__check_hash(curr_block)
            valid = valid and self.__check_prev_hash(prev_block, curr_block)
            valid = valid and self.__check_pow(curr_block)
            prev_block = curr_block
            if valid:
                valid_list.append(i)
                print(f'block {i} has been verified')
            else:
                invalid_list.append(i)
                print(f'block {i} verification failed')
        #end for
        
        self.__status: dict [str, list[int]] = {"valid" : valid_list,
                                         "invalid" : invalid_list}
        return len(invalid_list) == 0
    #end of verify

#end class BlockChain

microseconds_conversion = 1000000

def test_blockchain():
    blockchain: BlockChain = BlockChain()
    genesis: Block = Block(data = "Genesis block",
                           prevHash = None,
                           timeStamp = int(time.time() * microseconds_conversion),
                           prefix = 4)
    
    block1: Block = Block(data = "block-1",
                          prevHash = genesis.hash,
                          timeStamp = int(time.time() * microseconds_conversion),
                          prefix = 4)
    
    block2: Block = Block(data = "block-2",
                          prevHash = block1.hash,
                          timeStamp = int(time.time() * microseconds_conversion),
                          prefix = 8)
    
    block3: Block = Block(data = "block-3",
                          prevHash = block2.hash,
                          timeStamp = int(time.time() * microseconds_conversion),
                          prefix = 12)

    blockchain.addBlock(genesis)
    blockchain.addBlock(block1)
    blockchain.addBlock(block2)
    blockchain.addBlock(block3)

    if blockchain.verify():
        print("Block chain valid")
    else:
        print("Block chain invalid")

    print(blockchain.to_string())
#end test_blockchain

def main():
    test_blockchain()


if __name__ == "__main__":
    # Code to be executed when the script is run
    main()