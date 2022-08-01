// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/IERC20.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Counters.sol";

contract TokenDistribution is Ownable{

   using Counters for Counters.Counter;
   Counters.Counter public depositId;
   Counters.Counter public withdrawId;

   mapping(address => bool) public canBeUsedAsCurrency;
   address public babyDogeCoin;

   address public burnWallet;
   address public devWallet;
   
   struct Deposit{
       uint256 amount;
       address currency;
       address user;
    }

    struct Withdraw{
       uint256 amount;
       address user;
    }

    mapping(uint256 => Deposit) public idToDeposit;
    mapping(uint256 => Withdraw) public idToWithdraw;

   address public signer;
   address payable public treasury;

   mapping(uint256 => bool) public nonceUsed;

   event TokensDeposited(address indexed user, uint256 indexed amount, uint256 indexed id, 
   address currency);
   event Withdrawn(address indexed user, uint256 indexed amount, uint256 indexed id);
   event CurrencyUpdated(address token, bool canBeUsed);
   event SignerUpdated(address signer);
   event DevWalletUpdated(address wallet);
   event BurnWalletUpdated(address wallet);
   event TreasuryUpdated(address wallet);

   constructor(address coin, address burn, address dev, address _treasury, address _signer){
       babyDogeCoin =  coin;
       burnWallet = burn;
       devWallet = dev; 
       treasury = payable(_treasury);
       signer = _signer;
       canBeUsedAsCurrency[coin] = true;
       canBeUsedAsCurrency[address(0)] = true;
   }

   function updateCurrency(address token, bool canBeUsed) external onlyOwner{
       canBeUsedAsCurrency[token] = canBeUsed;
       emit CurrencyUpdated(token, canBeUsed);
   }

   function updateSigner(address signer_) external onlyOwner{
       signer = signer_;
       emit SignerUpdated(signer_);
   }

   function updateTreasury(address _treasury) external onlyOwner{
       treasury = payable(_treasury);
       emit TreasuryUpdated(_treasury);
   }

   function updateBurnWallet(address wallet) external onlyOwner{
       burnWallet = wallet;
       emit BurnWalletUpdated(wallet);
   }

   function updateDevWallet(address wallet) external onlyOwner{
       devWallet = wallet;
       emit DevWalletUpdated(wallet);
   }



   function depositTokens(address token, uint256 amount) external payable {

     require(canBeUsedAsCurrency[token], "Invalid Currency");
     if(token == address(0)){
      payable(devWallet).transfer(msg.value);
     }
     else{
      IERC20(token).transferFrom(msg.sender, burnWallet, amount);
     }
     uint256 deposit = depositId.current();
      idToDeposit[deposit] = Deposit({
        amount : amount,
        currency :  token,
        user : msg.sender
      });
      
      depositId.increment();
      emit TokensDeposited(msg.sender, amount, deposit, token);
     
   }


   function depositTokensTest(address token, uint256 amount ) external payable {

     require(canBeUsedAsCurrency[token], "Invalid Currency");
     uint256 deposit = depositId.current();
      idToDeposit[deposit] = Deposit({
        amount : amount,
        currency :  token,
        user : msg.sender
      });
      
      depositId.increment();

     if(token == address(0)){
      payable(treasury).transfer(msg.value);
       emit TokensDeposited(msg.sender, msg.value, deposit, token);
     }
     else{
      IERC20(token).transferFrom(msg.sender, treasury, amount);
       emit TokensDeposited(msg.sender, amount, deposit, token);
     }
         
     
   }

   function hashTransaction(
        address token,
        uint256 nonce,
        address wallet,
        uint256 tokenQuantity,
        string memory method
    ) public pure returns (bytes32) { 
        bytes32 hash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encodePacked(token,nonce, wallet, tokenQuantity, method))
            )
        ); 
        return hash;
    }

     function isValidData(bytes32 message, uint8 v, bytes32 r, bytes32 s) public view returns(bool){
       return (recoverSigner(message, v,r,s) == signer);
   }

   function recoverSigner(bytes32 message,  uint8 v, bytes32 r, bytes32 s)
       public
       pure
       returns (address)
     {
      
       return ecrecover(message, v, r, s);
   }



     function withdrawTokens(uint256 amount, 
     uint256 nonce, uint8 v, bytes32 r, bytes32 s ) external {
   
     require(nonceUsed[nonce]==false,"Nonce Used");
     bytes32 hash = hashTransaction(babyDogeCoin, nonce, msg.sender, amount, "withdraw");
     require(isValidData(hash, v, r, s),"Invalid Entry");
    
      IERC20(babyDogeCoin).transferFrom(treasury, msg.sender, amount);

      uint256 withdraw = withdrawId.current();
      idToWithdraw[withdraw] = Withdraw({
        amount : amount,
        user : msg.sender
      });
      
      withdrawId.increment();
      
      emit Withdrawn(msg.sender, amount, withdraw);
     
     
   }

    function withdrawTokensTest(uint256 amount) external  {
 
      IERC20(babyDogeCoin).transferFrom(treasury, msg.sender, amount);

      uint256 withdraw = withdrawId.current();
      idToWithdraw[withdraw] = Withdraw({
        amount : amount,
        user : msg.sender
      });
      
      withdrawId.increment();
      
      emit Withdrawn(msg.sender, amount, withdraw);
     
     
   }
}
