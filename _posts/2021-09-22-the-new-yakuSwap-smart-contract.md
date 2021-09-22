---
title: The new yakuSwap Ethereum Smart Contract
author: yakuhito
layout: post
permalink: /the-new-yakuSwap-ethereum-smart-contract
image: https://github.com/ethereum/ethereum-org/raw/master/public/images/logos/ETHEREUM-_LOGO-AND-TYPEFACE_LAN-small.png
category: blog
---

HTLCs are not that hard to implement, right?

## Intro

If you've been following me for the last month or so, you already know my main side-project: yakuSwap. The next step for the project is to support Chia-Ethereum atomic swaps, a target which definitely turned out to be more difficult to achieve than I initially thought. This post should explain the upgrades and the optimizations the contract underwent since the first release on github. For reference, here's my first attempt at implementing an HTLC:

{% highlight solidity %}
//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";

contract yakuSwap is Ownable {

  // Uninitialized - Default status (if swaps[index] doesn't exist, status will get this value)
  // Created - the swap was created, but the none is still in the contract
  // Completed - the money has been sent to 'toAddress' (swap successful)
  // Cancelled - the money has been sent to 'fromAddress' (maxBlockHeight was reached)
  enum SwapStatus { Uninitialized, Created, Completed, Cancelled }

  struct Swap {
    SwapStatus status;
    uint startBlock;
    uint amount;
    address fromAddress;
    address toAddress;
    uint16 maxBlockHeight;
  }

  mapping (bytes32 => Swap) public swaps; // key = secretHash
  uint public totalFees = 0;

  function createSwap(bytes32 _secretHash, address _toAddress, uint16 _maxBlockHeight) payable public {
    require(msg.value >= 1000);
    require(_maxBlockHeight > 10);
    require(swaps[_secretHash].status == SwapStatus.Uninitialized);
    require(_toAddress != address(0) && msg.sender != address(0));

    uint swapAmount = msg.value / 1000 * 993;
    Swap memory newSwap = Swap(
      SwapStatus.Created,
      block.number,
      swapAmount,
      msg.sender,
      _toAddress,
      _maxBlockHeight
    );

    swaps[_secretHash] = newSwap;
    totalFees += msg.value - newSwap.amount;
  }

  function completeSwap(bytes32 _secretHash, string memory _secret) public {
    Swap storage swap = swaps[_secretHash];

    require(swap.status == SwapStatus.Created);
    require(block.number < swap.startBlock + swap.maxBlockHeight);
    require(_secretHash == sha256(abi.encodePacked(_secret)));

    swap.status = SwapStatus.Completed;
    payable(swap.toAddress).transfer(swap.amount);
  }

  function cancelSwap(bytes32 _secretHash) public {
    Swap storage swap = swaps[_secretHash];

    require(swap.status == SwapStatus.Created);
    require(block.number >= swap.startBlock + swap.maxBlockHeight);

    swap.status = SwapStatus.Cancelled;
    payable(swap.fromAddress).transfer(swap.amount);
  }

  function getFees() public onlyOwner {
    totalFees = 0;
    payable(owner()).transfer(totalFees);
  }
}
{% endhighlight %}

## Pre-Optimisation Era

### Front-Runnable Functions
Commit(s): [1](https://github.com/Yakuhito/yakuSwap-eth/commit/6e063faf5c6695971cc88703be705b28a7fc6262)

In Ethereum, like in most other cryptocurrencies, a transaction gets sent to nodes before it's included in the blockchain. This means that everyone can see the data you send to a contract before your transaction is confirmed.

To understand front-running, let's look at a simple example. I want to protect my ether with a password, so I come up with a 'clever' contract with two functions: one that accepts payments from anyone and one for withdrawals. The withdrawal function will send all of the contract's ether to anyone who manages to provide a string that hashes to a hardcoded value (which I get to choose). Since I'm the only one who knows the text that hashes to that hardcoded value, the contract is safe, right?

Nope. Let's say you're an attacker and you want to get the 7 ether locked up in the contract. You don't have the secret value, so you can't get it - at least for now. What you can do, however, is monitor unconfirmed transactions and wait for me to provide the 'password'. Once you have it, you can just call the withdrawal function with a substantially bigger fee - that way, your transaction will likely be included in the blockchain before mine.

In the contract above, the problematic function is `createSwap`. If you read the code, you'll notice that swaps are stored in a mapping and that they're identified by their secret hash. No two trades should have the same secret hash (since that would be REALLY unsafe), so the key is definitely unique. The problem, however, is that an attacker might search the pending transactions for secret hashes and front-run users by using the same secret hash to create another swap, effectively blocking normal users from creating swaps.

As a fix, I included the secret hash in the swap structure and calculated the swap's id (mapping key) based on the secret hash as well as the initiator address (`fromAddress`). This way, an attacker can't front-run someone when they initiate a swap.

### transfer, send, and call
Commit(s): [1](https://github.com/Yakuhito/yakuSwap-eth/commit/6e063faf5c6695971cc88703be705b28a7fc6262) [2](https://github.com/Yakuhito/yakuSwap-eth/commit/1c0a71a532e776e2b50cbd5b3599dfd226cdc0ba) [3](https://github.com/Yakuhito/yakuSwap-eth/commit/77c2e584fa1ff3cdbf493d58dcf024499037d84e)

I'll be honest: the Solidity tutorials I've followed didn't really explain the difference between `transfer`, `send`, and `call`, so I wasn't exactly sure how I was supposed to send ether to someone else. I first used `transfer` because I read that it automatically reverts if the transfer fails, but then somebody told me to use `send`. After more research, I found out that I was supposed to use `call` - that covers commits [1](https://github.com/Yakuhito/yakuSwap-eth/commit/6e063faf5c6695971cc88703be705b28a7fc6262) and [2](https://github.com/Yakuhito/yakuSwap-eth/commit/1c0a71a532e776e2b50cbd5b3599dfd226cdc0ba).

When I replaced `send` with `call`, I did reverts manually, like this: 

{% highlight solidity %}
(bool success,) = swap.toAddress.call{value: swap.amount}("");
if(!success) {
  swap.status = SwapStatus.Created;
}
{% endhighlight %}

[Commit 3](https://github.com/Yakuhito/yakuSwap-eth/commit/77c2e584fa1ff3cdbf493d58dcf024499037d84e) changes all `if` statements with `require(success);`, which does the exact same job, but makes the code cleaner and less error-prone.

### Events
Commit(s): [1](https://github.com/Yakuhito/yakuSwap-eth/commit/786fb78a693ea1265a2ed2ab529eed3624a75684)

If somebody reveals the secret to complete a swap, how are clients supposed to find it? For Ethereum, the answer is events. Contracts emit events that contain data and clients can later query events by their name and the data markqed as `indexed`.

## Optimisation Era

I had the pleasure of watching [shark0der](https://twitter.com/shark0der) optimize this contract. To get an idea of how good his ideas were, take a look at [this comparison](https://twitter.com/yakuh1t0/status/1436335461136470017?s=20).

Global commits: [1](https://github.com/Yakuhito/yakuSwap-eth/commit/1490b08fbf8dce2759966e06a9848dc9fce3ba36)

### Fees? No fees!

You know yakuSwap takes a 0.7% fee for every trade, right? The fee is kept in the contract until I, the owner, call a function called `getFees`. This is the function's body:

{% highlight solidity %}
function getFees() public onlyOwner {
  totalFees = 0;
  (bool success,) = owner().call{value: totalFees}("");
    
  require(success);
}
{% endhighlight %}

Did you spot the problem? I tried to optimize the contract too much and I ended up assigning `totalFees` to 0 and sending myself `totalFees`, which was 0. The function was 'clearing' `totalFees`, not sending me the actual trade fees - good thing shark0der spotted that before I deployed the contract!

As a side note, the contract's tests included this function. However, they did not check the owner's balance after the function was called - the test just asserted that `totalFees` became 0, which happened every time...

### Contract Name

I initially named the contract `yakuSwap`, but there seems to be a convention that contract names should start with a capital letter. Plus, the deployment code became a lot cleaner.

Before:
{% highlight solidity %}
yakuSwapContractFactory = await ethers.getContractFactory("yakuSwap");
yakuSwap = await yakuSwapContractFactory.deploy();    
{% endhighlight %}

After:
{% highlight solidity %}
const YakuSwap = await ethers.getContractFactory('YakuSwap');
yakuSwap = await YakuSwap.deploy();
{% endhighlight %}

### Slots

Apparently, the amount of gas used depends on the number of storage slots a function reads and/or writes. A slot can contain up to 32 bytes, or 256 bits. The `Swap` struct was updated to only use 3 slots:

{% highlight solidity %}
struct Swap {
  bytes32 secretHash;

  uint96 amount;
  address fromAddress;

  address toAddress;
  SwapStatus status;
  uint32 startBlock;
  uint16 maxBlockHeight;
}
{% endhighlight %}

However, there's an even better alternative: use one slot. The secret is to hash all of the swap's data except the status and use the result as a key. The value can be limited to the swap's status, since that's the only field the contract updates. To make sure that swap-related data is accessible, we can just emit an event once the swap has been created.

### internal and external
Changing functions from 'public/private' to 'external/internal' might save gas - calling a `public` function from inside the contract consumes more gas than calling an `internal` one.

Here's a very interesting optimization of the contract:

{% highlight solidity %}
function _getSwapHash(
  address fromAddress,
  address toAddress,
  uint value,
  bytes32 secretHash,
  uint blockNumber
) internal view returns (bytes32) {
  return keccak256(
    abi.encode(
      fromAddress,
      toAddress,
      value,
      secretHash,
      blockNumber,
      block.chainid
    )
  );
}

function getSwapHash(
  address fromAddress,
  address toAddress,
  uint value,
  bytes32 secretHash,
  uint blockNumber
) external view returns (bytes32) {
  return _getSwapHash(
    fromAddress, toAddress, value, secretHash, blockNumber
  );
}
{% endhighlight %}

The `getSwapHash` function calls the internal `_getSwapHash` method, which calculates the hash for a given swap. The reason is simple: since most of the contract's functions need to get the swap's hash, making the function `internal` might save some gas. However, the method also needs to be called from the outside - since it's a `view` function, adding a 'wrapper function' doesn't consume any gas (except the one used for deploying the contract).

### HAL 9000
I'm talking about Solidity's compiler optimizer. Without the optimizer, the final contract (the one you'll see near the end of the article) would cost about 1700000 gas to deploy. The optimizer turned that into 900000, not to mention that every method call will consume a little less gas - turning it on was worth it!

Note: The optimizer usually INCREASES the contract size in order to minimize the gas required to execute the contract's methods; this was just a happy occurrence.

### require
`require` statements accept a second parameter, a reason string. Even though it might take a little more gas, you should always tell your users why the contract failed.

## Post-Optimisation Era

After I was pretty sure the gas consumed by the contract couldn't be significantly reduced anymore, I started looking into Arbitrum, Optimism, and Polygon. These are layer-2 solutions that help reduce transaction fees. For normal users, they're also 'separate' Ethereum networks - you just need to add a new network to MetaMask and everything just works (plus, transferring ether to them via a bridge is straight-forward)!

The downside is that these networks use optimistic roll-ups, so an user wanting to withdraw their ether from Arbitrum to mainnet would have to wait one week for their transaction to go through. That's not a problem, though, since a lot of DeFi apps have already deployed their contracts to one of these networks as well.

Still, supporting these networks was just a matter of deploying the contract on each one and adding a UI dropdown in the client. There was one more improvement I couldn't get out of my head.

### TOKENSSS!
Commit(s): [1](https://github.com/Yakuhito/yakuSwap-eth/commit/179bb5d327081fad707983644d506c8bd9fef371)

Wrapped Ether (WETH) is a token that can be converted 1:1 to ether any time. Swapping Chia for ether is cool, but have you ever tried swapping it for WETH? It's even better! The reason is simple: once your contract supports one ERC20 token, it can support all of them.

In short, the ERC-20 specification defines some standard methods that a token contract should have. For example, the `balanceOf(address)` returns the token balance of a given address - that's true for any ERC-20 token. Knowing that they can interact with all ERC-20 tokens the same, developers only need to take care of one thing: get the token contract's address.

Fortunately, that's not a problem for yakuSwap. The list can be built, updated, and parsed by the client, off-chain. There are only 3 main changes in the contract:
1. Each swap should also have a `tokenAddress` attribute, which represents the token contract's address on the current network.
2. All ether transfers should be replaced with token transfers. Surprisingly, transferring tokens is not harder than transferring ether.
3. Fees have to be stored for each individual token.

I managed to modify the contract's tests way faster than I initially expected - there were more than enough examples online.

### OZ Rules
Commit(s): [1](https://github.com/Yakuhito/yakuSwap-eth/commit/4ae86a7ba090121f7b8ced7efdb310dbb0c8da03)

Just as I was getting ready to post this article, another potential improvement got pointed out: instead of my custom `IERC20` interface, I could use OpenZeppelin's one (which is known to work correctly) along with `SafeERC20`.

## The end?
Now that you know what the contract went through, you probably agree that writing smart contracts, even simple ones, is not as easy as it seems. I'm almost 100% sure that this is not the final version of the yakuSwap contract - I just hope it's the first version that the app's users use.

I'd tell you what the next article is going to be about, but I'm not sure of that myself. <!-- One of the next articles: df567e66993d60837854477ad68bb3b6 e528085e1d953a93bc765b3aab4d743ceb4cfef0da0c167145aa7d31944de564 bc4a340a7eda4caee65fded5945a1c8a6560b7bb4ffee2c4bee83b396659d0b2e76246d766f25b6e510ff480826588149e3f20b38d6ccfee9dd34b1fb75fc1a8 -->

Until next time, hack the world.

yakuhito, over.