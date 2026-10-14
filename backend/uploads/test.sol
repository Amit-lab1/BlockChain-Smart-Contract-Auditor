pragma solidity ^0.8.0;

contract TestContract {

    uint public balance;

    function deposit() public payable {
        balance += msg.value;
    }

    function withdraw(uint amount) public {
        payable(msg.sender).transfer(amount);
        balance -= amount;
    }
}