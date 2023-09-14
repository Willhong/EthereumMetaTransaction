// SPDX-License-Identifier: MIT
pragma solidity >=0.8.2 <0.9.0;

interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract MultiTransfer {
    address public owner;

    // EIP-712 type data
    bytes32 private constant META_TRANSACTION_TYPEHASH = keccak256(bytes(
        "MetaTransaction(uint256 nonce,address from,bytes functionSignature)"
    ));
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(bytes(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    ));
    bytes32 private domainSeparator;

    mapping(address => uint256) private nonces;

    event MetaTransactionExecuted(address userAddress, address relayerAddress, bytes functionSignature);

    struct Transaction{
            address from;
            address to;
            uint256 amount;
            uint256 timestamp;
        }

    constructor() payable {
        owner = msg.sender;
        domainSeparator = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256(bytes("MultiTransfer")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }
    mapping(uint256=>Transaction) private _transaction;
    uint256 transactioncount;
    event TransactionSent(address indexed from, address indexed to, uint256 amount, uint256 timestamp);

    function executeMetaTransaction(address userAddress, bytes memory functionSignature, bytes32 sigR, bytes32 sigS, uint8 sigV) public returns(bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparator,
            keccak256(abi.encode(META_TRANSACTION_TYPEHASH, nonces[userAddress]++, userAddress, keccak256(functionSignature)))
        ));

        require(userAddress != address(0), "Invalid user address");
        require(userAddress == ecrecover(digest, sigV, sigR, sigS), "Signature is invalid");

        emit MetaTransactionExecuted(userAddress, msg.sender, functionSignature);

        (bool success, bytes memory returnData) = address(this).delegatecall(functionSignature);
        require(success, "Function call failed");

        return returnData;
    }

    function getNonce(address user) external view returns(uint256) {
        return nonces[user];
    }
    modifier onlyOwner() {
        require(msg.sender == owner, "You are not the owner");
        _;
    }

    function deposit() external payable {}

    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
    address public pendingOwner;

    event OwnershipTransferInitiated(address indexed currentOwner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "New owner cannot be the zero address");
        pendingOwner = newOwner;
        emit OwnershipTransferInitiated(owner, pendingOwner);
    }

    function claimOwnership() public {
        require(msg.sender == pendingOwner, "Only the pending owner can claim ownership");
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

   function multiSendToken(address token, address[] memory recipients, uint256[] memory amounts) public {
        require(recipients.length == amounts.length, "Recipients and amounts arrays must have the same length");

        IERC20 erc20Token = IERC20(token);

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < recipients.length; i++) {
            require(amounts[i] > 0, "Invalid Amount");
            require(erc20Token.transferFrom(msg.sender, recipients[i], amounts[i]), "Transfer failed for some recipient");
            
            _transaction[transactioncount] = Transaction(owner, recipients[i], amounts[i], block.timestamp);
            totalAmount += amounts[i];
            transactioncount++;

            emit TransactionSent(msg.sender, recipients[i], amounts[i], block.timestamp);
        }

        require(erc20Token.balanceOf(msg.sender) >= totalAmount, "Invalid Balance");
    }

    function multiSendEther(address[] memory recipients, uint256[] memory amounts) public payable {
        require(recipients.length == amounts.length, "Recipients and amounts arrays must have the same length");
        
        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            totalAmount += amounts[i];
        }
        require(msg.value == totalAmount, "Sent ether value does not match the total amounts to send");

        for (uint256 i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(amounts[i]);
        }
    }

    function getBalance(address tokenAddress, address account) external view returns (uint256) {
        IERC20 token = IERC20(tokenAddress);
        return token.balanceOf(account);
    }
}
