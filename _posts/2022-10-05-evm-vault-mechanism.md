---
title: DownUnderCTF 2022 - EVM Vault Mechanism
author: yakuhito
layout: post
permalink: /downunderctf-2022-evm-vault-mechanism
image: /images/evm-vault-mechanism.png
category: blog
---

long time no see - still no see since you're **reading** this article

## The Introor

I'm not sure exactly when, but DownUnderCTF took place some time in the last 14 days. I spent the whole CTF solving the blockchain category, with the majority of my time being allocated to a challenge titled 'EVM Vault Mechanism'. From my point of view, this was the hardest and most interesting blockchain challenge, so I thought doing a write-up post would be nice. You can find the other challenges, my solution, and very short explanations for each one [in this GitHub repo](https://github.com/Yakuhito/DownUnderCTF-2022).

## The Contextoor

The 'hard' challenge that I finished before starting this one was pretty straightforward, so I didn't expect much. However, as soon as I opened the challenge description, I knew something was wrong - there were no `.sol` files available for download!

<div>
<center>
<iframe src="https://giphy.com/embed/UQYtr98lNNrWw" width="480" height="204" frameBorder="0" class="giphy-embed" allowFullScreen></iframe>
</center>
</div>

Don't worry, though - if I managed to solve this challenge, anyone can! While reading, just remember that some tasks just require the willingness to learn and (lots of) time.

## The Decompilatoor

At this point, I there are 2 pieces of information available for the challenge:
 * The challenge title & description: 'EVM Vault Mechanism' and 'Unlock the vault and the treasures are yours.'
 * The blockchain

Each player has their personal RPC endpoint, so the blockchain only contains 'setup' transactions in the beginning. Here's how to get the transaction blocks with ethers:

{% highlight js %}
console.log(await ethers.provider.getBlockWithTransactions(1));
// block 1 - tx to give ether to the player account
console.log(await ethers.provider.getBlockWithTransactions(2));
// block 2 - bytecode deployment
console.log(await ethers.provider.getBlockWithTransactions(3));
// block 3 - null -> only 2 blocks
{% endhighlight %}

The bytecode was deployed in the 2nd block and looks like this:

{% highlight python %}
0x6102c56100106000396102c56000f3fe600836101561000e5760006000fd5b610168565b600065069b135a06c38201608081029050650b3abdcef1f18118905080660346d81803d47114159150505b919050565b600081600f526004600f2066fd28448c97d19c8160c81c14159150505b919050565b6000338031813b823f63ff000000811660181c6004600b6007873c600460072060ff811660778114838614670de0b6b3a76400008811607760ff8b1614020202159750505050505050505b919050565b600062ffff00821660081c600d8160071b0160020260ff8460181c166101010260ff60ff8616600202166003014303408083018218600014159450505050505b919050565b6000303f806007526000600060005b6020811015610142576001600187831c1614156101365760ff600751600883021c16830192506001820191505b5b600181019050610109565b50601181146105398306610309140293505050505b919050565b6000600090505b919050565b60003560e01c60043560e01c81637672667981146101cc57634141414181146101ea576342424242811461020e57634343434381146102325763444444448114610256576345454545811461027a57634646464681146102a05760006000fd6102c0565b6113375460ff8114156101e457600165736f6c766564555b506102c0565b6101f382610013565b8015156102085761133754604a811861133755505b506102c0565b61021782610043565b80151561022c576113375460d1811861133755505b506102c0565b61023b82610065565b80151561025057611337546064811861133755505b506102c0565b61025f826100b5565b801515610274576113375460b2811861133755505b506102c0565b610283826100fa565b600181141561029a57611337546063811861133755505b506102c0565b6102a98261015c565b8015156102be576113375460c4811861133755505b505b50005050
{% endhighlight %}

In order to solve the challenge, we'll first need to read the bytecode. After failing to decompile it to Solidity code multiple times, I accepted the fact that I'll probably have to reverse engineer assembly code to see what the contract does.

During my search for the ultimate evm decompiler, I stumbled upon [evmdis](https://github.com/Arachnid/evmdis), which disassembled the bytecode quite well. After installing it with `go`, I wrote the bytecode in a file and used the following command:

{% highlight bash %}
evmdis -ctor -bin < EVMVaultMechanism.sol.bin
{% endhighlight %}

If you want to see the result, see [EVMVaultMechanism.sol.disassembled](https://github.com/Yakuhito/DownUnderCTF-2022/blob/master/contracts/EVMVaultMechanism.sol.disassembled) in the write-up repo.

As you'll soon see, 387 lines are not that much.

## The Function Selectoor

Now that we have the disassembled bytecode, solving the challenge is just a matter of understanding what we're seeing. Let's start with the beginning of the code:

{% highlight python %}
# Constructor part -------------------------
# Stack: []
0x8     CODECOPY(0x0, 0x10, 0x2C5)
0xE     RETURN(0x0, 0x2C5)

# Code part -------------------------
# Stack: []
0x8     JUMPI(:label0, !(CALLDATASIZE() < 0x8))

# Stack: []
0x9     PUSH(0x0)
0xB     PUSH(0x0)
0xD     REVERT()

:label0
# Stack: []
0x12    JUMP(:label10)
{% endhighlight %}

The constructor part can be safely ignored for now. The code does a conditional jump to `label0` if the calldata size is greater than or equal to 8. If the jump doesn't happen, the code will revert, meaning that we need to call this contract with at least 8 bytes of data. `label0` just does a jump to `label10`:

{% highlight python %}
:label10
# Stack: []
0x16E   PUSH(SHR(0xE0, CALLDATALOAD(0x0)))
0x174   PUSH(SHR(0xE0, CALLDATALOAD(0x4)))
0x175   DUP2
0x17B   DUP1
0x180   JUMPI(:label11, POP(@0x16E) == 0x76726679)

# Stack: [@0x16E @0x174 @0x16E]
0x186   DUP1
0x18B   JUMPI(:label13, POP(@0x16E) == 0x41414141)

# Stack: [@0x16E @0x174 @0x16E]
0x191   DUP1
0x196   JUMPI(:label16, POP(@0x16E) == 0x42424242)

# Stack: [@0x16E @0x174 @0x16E]
0x19C   DUP1
0x1A1   JUMPI(:label19, POP(@0x16E) == 0x43434343)

# Stack: [@0x16E @0x174 @0x16E]
0x1A7   DUP1
0x1AC   JUMPI(:label22, POP(@0x16E) == 0x44444444)

# Stack: [@0x16E @0x174 @0x16E]
0x1B2   DUP1
0x1B7   JUMPI(:label25, POP(@0x16E) == 0x45454545)

# Stack: [@0x16E @0x174 @0x16E]
0x1BD   DUP1
0x1C2   JUMPI(:label28, POP(@0x16E) == 0x46464646)

# Stack: [@0x16E @0x174 @0x16E]
0x1C3   PUSH(0x0)
0x1C5   PUSH(0x0)
0x1C7   REVERT()
{% endhighlight %}

Take a deep breath and don't panic. This function is not very hard to reverse - it's very similar to Solidity's function selector. The first two lines basically divide the first 8 bytes of calldata into 2 values / halves. Then, depending on the first half, a conditional jump will be taken or the contract will revert.

The function 'names' are `0x76726679`, `0x41414141`, ...,`0x46464646`, or, in ASCII, `vrfy`, `AAAA`, ..., `FFFF`. Each one is going to handle the second argument differently by getting it with `POP(@0x174)`.

## The Validatoor

We still don't know what the challenge is about, so the best course of action is to start with the `vrfy` function. Judging by its name, the function is supposed to verify something, maybe if the challenge was solved. The function selector takes us to `label11`:

{% highlight python %}
:label11
# Stack: [@0x16E @0x174 @0x16E]
0x1D0   PUSH(SLOAD(0x1337))
0x1D3   DUP1
0x1D9   JUMPI(:label12, !(POP(@0x1D0) == 0xFF))

# Stack: [@0x1D0 @0x16E @0x174 @0x16E]
0x1E3   SSTORE(0x736F6C766564, 0x1)

:label12
# Stack: [@0x1D0 @0x16E @0x174 @0x16E]
0x1E5   POP()
0x1E9   JUMP(:label31)
{% endhighlight %}

The code loads a value located at storage slot `0x1337`. If it is equal to `0xFF`, it will set storage slot `0x736F6C766564` (ASCII: 'solved') to 1. The code will then jump to `label31`, no matter what the value is:

{% highlight python %}
:label31
# Stack: [@0x16E @0x174 @0x16E]
0x2C1   POP()
0x2C2   STOP()
{% endhighlight %}

`label31` gracefully stops the execution of the code, much like a `return` statement would. Keep this in mind - it's referenced in a lot of places.

## The Generalizoor

Okay, so we need to set the storage slot at `0x1337` to `0xFF`. It would be nice to see if functions `AAAA` through `FFFF` follow a 'template' - let's follow the execution flow of `AAAA` to get a sense of what it's doing, starting at `label13` (see function selector):

{% highlight python %}
:label13
# Stack: [@0x16E @0x174 @0x16E]
0x1EB   PUSH(:label14)
0x1EE   DUP3
0x1F2   JUMP(:label1)
{% endhighlight %}

That looks pretty strange, but the function is only pushing another reference to the stack (maybe a callback?) and calls `label1`:

{% highlight python %}
:label1
# Stack: [@0x174 :label14 @0x16E @0x174 @0x16E]
0x14    PUSH(0x0)
0x1D    DUP1
0x1E    PUSH(POP(@0x174) + 0x69B135A06C3)
0x21    DUP1
0x22    PUSH(POP(@0x1E) * 0x80)
0x23    SWAP1
0x24    POP()
0x2C    DUP1
0x2D    PUSH(POP(@0x22) ^ 0xB3ABDCEF1F1)
0x2E    SWAP1
0x2F    POP()
0x30    DUP1
0x3A    PUSH(!(0x346D81803D471 == POP(@0x2D)))
0x3B    SWAP2
0x3C    POP()
0x3D    POP()

# Stack: [@0x3A @0x174 :label14 @0x16E @0x174 @0x16E]
0x3F    SWAP2
0x40    SWAP1
0x41    POP()
0x42    JUMP(POP(:label14))
{% endhighlight %}

There's some fancy math going on, but, for now, we're interested in the general execution flow of the code. Notice that the last line jumps to the thing I compared to a callback, `label14`:

{% highlight python %}
:label14
# Stack: [@0x3A @0x16E @0x174 @0x16E]
0x1F4   DUP1
0x1FA   JUMPI(:label15, !!POP(@0x3A))

# Stack: [@0x3A @0x16E @0x174 @0x16E]
0x1FE   PUSH(SLOAD(0x1337))
0x201   DUP1
0x206   SSTORE(0x1337, POP(@0x1FE) ^ 0x4A)
0x207   POP()

:label15
# Stack: [@0x3A @0x16E @0x174 @0x16E]
0x209   POP()
0x20D   JUMP(:label31)
{% endhighlight %}

There it is! The function jumps to `label15` if something 'returned' from `label1` is true. If the jump isn't taken, slot `0x1337` is XORed with `0x4A`. `label15` is then executed anyway, and it just jumps to `label31` (the `return` equivalent we looked at earlier).

It seems like we are getting somewhere! Indeed, each function executes some code and, based on something returned from the code, XORs storage slot `0x1337` with a value (or doesn't). Here's a list of the functions, their associated labels, and the value they XOR the slot with:

 * `AAAA` - `label13` - `0x4A`
 * `BBBB` - `label16` - `0xD1`
 * `CCCC` - `label19` - `0x64`
 * `DDDD` - `label22` - `0xB2`
 * `EEEE` - `label25` - `0x63`
 * `FFFF` - `label28` - `0xC4`

# The Thinkoor

A normal person would start reversing all functions at this point, but I'm really grateful that I did the following thing:

{% highlight python %}
>>> hex(0x4A ^ 0xD1 ^ 0x64 ^ 0xB2 ^ 0x63 ^ 0xC4)
'0xea'
{% endhighlight %}

Executing all functions would not be a good idea, since the slot's value wouldn't be `0xFF`. XOR is commutative and `x ^ x = 0` for all `x`, so calling a function twice is the same as not calling it at all. This means that we need to call each function at most once, but calling all of them won't work. The following python script prints all the possible function call combinations that will get storage slot `0x1337` to hold `0xFF`:

{% highlight python %}
import itertools

xor_values = [0x4A, 0xD1, 0x64, 0xB2, 0x63, 0xC4]

for subset_len in range(1, len(xor_values)):
    for subset in itertools.combinations(xor_values, subset_len):
        x = 0
        for elem in subset:
            x ^= elem
        if x == 0xFF:
            print(f"Found subset: {[hex(e) for e in subset]}")
{% endhighlight %}

The output suggests that we call any of the following combinations:
 * `AAAA` + `BBBB` + `CCCC`
 * `AAAA` + `CCCC` + `DDDD` + `EEEE`

We have to call two functions anyway (`AAAA` and `CCCC`), so we'll start reversing those.

## The AAAAoor

We've already taken a look at `AAAA`. To refresh your memory, here's the deconstruction of `lable1`: 

{% highlight python %}
:label1
# Stack: [@0x174 :label14 @0x16E @0x174 @0x16E]
0x14    PUSH(0x0)
0x1D    DUP1
0x1E    PUSH(POP(@0x174) + 0x69B135A06C3)
0x21    DUP1
0x22    PUSH(POP(@0x1E) * 0x80)
0x23    SWAP1
0x24    POP()
0x2C    DUP1
0x2D    PUSH(POP(@0x22) ^ 0xB3ABDCEF1F1)
0x2E    SWAP1
0x2F    POP()
0x30    DUP1
0x3A    PUSH(!(0x346D81803D471 == POP(@0x2D)))
0x3B    SWAP2
0x3C    POP()
0x3D    POP()

# Stack: [@0x3A @0x174 :label14 @0x16E @0x174 @0x16E]
0x3F    SWAP2
0x40    SWAP1
0x41    POP()
0x42    JUMP(POP(:label14))
{% endhighlight %}

Also, recall the condition of the conditional jump just before the XOR takes place:

{% highlight python %}
:label14
# Stack: [@0x3A @0x16E @0x174 @0x16E]
0x1F4   DUP1
0x1FA   JUMPI(:label15, !!POP(@0x3A))

# Stack: [@0x3A @0x16E @0x174 @0x16E]
0x1FE   PUSH(SLOAD(0x1337))
0x201   DUP1
0x206   SSTORE(0x1337, POP(@0x1FE) ^ 0x4A)
0x207   POP()
{% endhighlight %}

The code pushed at location `0x3A` needs to be true for the jump to be taken, so we actually need it to be false for the XOR to be false. The condition is `!(0x346D81803D471 == POP(@0x2D))` - adding a NOT will cancel the first one out, so we have `0x346D81803D471 == POP(@0x2D)`. If we replace `POP` instructions with the value pushed at the indicated code offset, we can deduce what the first argument should be:

{% highlight python %}
ARG1 - POP(@0x174)
0x346D81803D471 == ((POP(@0x174) + 0x69B135A06C3) * 0x80) ^ 0xB3ABDCEF1F1
0x346D81803D471 ^ 0xB3ABDCEF1F1 == ((ARG1 + 0x69B135A06C3) * 0x80)
0x34de2a5cd2580 // 0x80 == ARG1 + 0x69B135A06C3
0x69bc54b9a4b == ARG1 + 0x69B135A06C3
ARG1 = 0xb1f19388
{% endhighlight %}

That's it! Calling the vault contract with the calldata `0x41414141b1f19388` will indeed xor the value of storage slot `0x1337`.

## The CCCCoor
Ladies and gentlemen, please fasten your seatbelts. This is the hardest 'pin' to unlock - you'll see why in a moment.

Let's first look at `label19` and `label20`, which are responsible for calling the real function and comparing the result:

{% highlight python %}
:label19
# Stack: [@0x16E @0x174 @0x16E]
0x233   PUSH(:label20)
0x236   DUP3
0x23A   JUMP(:label3)

:label20
# Stack: [@0xA6 @0x16E @0x174 @0x16E]
0x23C   DUP1
0x242   JUMPI(:label21, !!POP(@0xA6))

# Stack: [@0xA6 @0x16E @0x174 @0x16E]
0x246   PUSH(SLOAD(0x1337))
0x249   DUP1
0x24E   SSTORE(0x1337, POP(@0x246) ^ 0x64)
0x24F   POP()

:label21
# Stack: [@0xA6 @0x16E @0x174 @0x16E]
0x251   POP()
0x255   JUMP(:label31)
{% endhighlight %}

The `POP(@0xA6)` instruction needs to return false for the XOR operation to happen. Let's take a look at `label3`:

{% highlight python %}
:label3
# Stack: [@0x174 :label20 @0x16E @0x174 @0x16E]
0x66    PUSH(0x0)
0x68    PUSH(CALLER())
0x69    DUP1
0x6A    PUSH(BALANCE(POP(@0x68)))
0x6B    DUP2
0x6C    PUSH(EXTCODESIZE(POP(@0x68)))
0x6D    DUP3
0x6E    PUSH(EXTCODEHASH(POP(@0x68)))
0x74    DUP1
0x78    PUSH(SHR(0x18, POP(@0x6E) & 0xFF000000))
0x7F    DUP5
0x80    EXTCODECOPY(POP(@0x68), 0x7, 0xB, 0x4)
0x85    PUSH(SHA3(0x7, 0x4))
0x88    DUP1
0x89    PUSH(POP(@0x85) & 0xFF)
0x8C    DUP1
0x8E    DUP3
0x8F    DUP6
0x9A    DUP6
0xA0    DUP7
0xA6    PUSH(!((POP(@0x68) & 0xFF == 0x77) * (POP(@0x6A) > 0xDE0B6B3A7640000) * (POP(@0x6C) == POP(@0x78)) * (POP(@0x89) == 0x77)))
0xA7    SWAP8
0xA8    POP()
0xA9    POP()
0xAA    POP()
0xAB    POP()
0xAC    POP()
0xAD    POP()
0xAE    POP()
0xAF    POP()

# Stack: [@0xA6 @0x174 :label20 @0x16E @0x174 @0x16E]
0xB1    SWAP2
0xB2    SWAP1
0xB3    POP()
0xB4    JUMP(POP(:label20))
{% endhighlight %}

Don't worry - the constraints are not too hard to figure out. `0x68` pushes `msg.sender` on the stack. `0x6A` pushes the balance of `msg.sender`, `0x6C` its code size, and `0x6E` its hash. Notice that these are all things that we can control.

We want the value pushed at `0xA6` to be false, but it starts with a negation (`!`). Since a double negation 'cancels itself out' (i.e., not not false is false and not not true is true), we need to satisfy the following condition:

{% highlight python %}
(POP(@0x68) & 0xFF == 0x77) *
(POP(@0x6A) > 0xDE0B6B3A7640000) *
(POP(@0x6C) == POP(@0x78)) *
(POP(@0x89) == 0x77)
{% endhighlight %}

Multiplying values is the equivalent of `AND` (`&&`), since, if any of them are 0, the result will also be 0. That means that we are going to keep 4 constraints in mind while designing the contract that will call the vault (you'll see later that only a special contract can satisfy these constraints).

Let's start with the first one, `POP(@0x68) & 0xFF == 0x77`. This basically says that the address of the calling contract needs to end with `77`. This is easily doable by bruteforcing the `salt` of [`CREATE2`](https://solidity-by-example.org/app/create2/) - a function that lets us determine a contract's address before deploying it.

The second one is `POP(@0x6A) > 0xDE0B6B3A7640000`. This is, again, a very simple constraint to satisfy: it just asserts that `msg.sender`'s balance is greater than `10 ^ 18` wei, which is the equivalent of one ether.

You might think that the two other constraints are just as easy to satisfy, but you'd be extremely wrong. I'll start with `POP(@0x89) == 0x77`, since the third one should be approached last (it relies on the contract's hash). The constraint says that `POP(@0x85) & 0xFF` should be equal to `0x77`. But, if you look at the code, `0x85` is `SHA3(0x7, 0x4)`. The `0x7` storage slot is assigned one line before: `EXTCODECOPY(POP(@0x68), 0x7, 0xB, 0x4)`.

Okay, let's recap. The contract copies 4 bytes of code from the calling contract (offset `0xB`), hashes them, and then checks the last bytes of the `SHA3` hash. To design a contract that fits this constraint, we first have to find one of the many possible 4-byte values that will work:

{% highlight python %}
import sha3

i = 0x12345678
limit = 256 * 256 * 256 * 256

def check(i):
    b = bytes.fromhex(hex(i)[2:].rjust(8, "0"))
    print(b)
    k = sha3.keccak_256()
    k.update(b)
    if (int(k.hexdigest(), 16) & 0xFF) == 0x77:
        return True
    return False


while i < limit:
    if check(i):
        print("FOUND ID")
        print(hex(i))
        break
    elif i % 0xfffff == 0:
        print(hex(i))
    i += 1
{% endhighlight %}

If you run the code, you'll see that the output is `0x1234576c`. But where should we keep this value? To find out, let's use the following skeleton code for our contract:

{% highlight python %}
pragma solidity ^0.8.0;

contract Constructoor {
    address private vault;

    constructor(address _vault) {
        vault = _vault;
    }

    fallback() external payable {
        uint256 a = 0x4343434331333337000000000000000000000000000000000000000000000000;
        address _vault = vault;
        assembly {
            mstore(0x7, a)
            a := call(
                10000000000,
                _vault,
                0,
                0x7,
                8,
                0x13,
                0
            )
        }
    }
}
{% endhighlight %}

The `fallback` function uses some assembly in order to make the resulting shellcode shorter - I'm not sure if that is required, but it was fun making a call with in-line assembly. If we deploy this contract, and get its code at offset `0xB`, we will get `0x331333337`, which is exactly our call value! I still didn't want to ruin such a nice function argument (it's '1337' in ASCII), so I declared another variable before it:

{% highlight python %}
pragma solidity ^0.8.0;

contract Constructoor {
    address private vault;

    constructor(address _vault) {
        vault = _vault;
    }

    fallback() external payable {
        //                       |      | for bytecode loaded == 0x77
        uint256 thingy = 0xffffff1234576c00000000000000000000000000000000000000000000000000; // dice roll
        uint256 a = 0x4343434331333337000000000000000000000000000000000000000000000000;
        address _vault = vault;
        assembly {
            mstore(0x7, a)
            a := call(
                10000000000,
                _vault,
                0,
                0x7,
                8,
                0x13,
                0
            )
        }
    }
}
{% endhighlight %}

Indeed, that would satisfy the 3 constraints we have so far, since the contract address can be bruteforced before deployment, the bytecode contains the magic value at offset `0xB`, and the contract can be given funds when the `fallback` function is activated. Let's move on to the fourth and last constraint: `POP(@0x6C) == POP(@0x78)`. `0x6C` is the code size of the caller and `0x78` is `SHR(0x18, POP(@0x6E) & 0xFF000000)` (`0x6E` is the code hash of our contract). In other words, the byte located somewhere in the hash of the contract's code needs to match the code's length. Notice that `0x78` is only 1 byte long - the contract code can't be longer than 255 bytes.

At this point, some advanced users might try taking the 'metadata' that the solidity compiler adds at the end of compiled bytecode and change that. However, I am a yak with a blog, not an advanced user. I remembered that the `thingy` variable above had a lot of unused bytes and decided to put them to good use: I just incremented the value until I got a bytecode that fit the limitations:

{% highlight python %}
import sha3
from web3 import Web3
import solcx

i = 0xffffff1234576c00000000000000000000000000000000000000000000000000
replaceMe = "0xffffff1234576c00000000000000000000000000000000000000000000000000"

solcx.install_solc(version='0.8.9')
solcx.set_solc_version('0.8.9')

def check(i):
    compiled_sol = solcx.compile_source("""
pragma solidity ^0.8.0;

contract Constructoor {
    address private vault;

    constructor(address _vault) {
        vault = _vault;
    }

    fallback() external payable {
        //                       |      | for bytecode loaded == 0x77               salt for code (manually bf)
        uint256 thingy = 0xffffff1234576c00000000000000000000000000000000000000000000000000; // dice roll
        uint256 a = 0x4343434331333337000000000000000000000000000000000000000000000000;
        address _vault = vault;
        assembly {
            mstore(0x7, a)
            a := call(
                10000000000,
                _vault,
                0,
                0x7,
                8,
                0x13,
                0
            )
        }
    }
}
    """.replace(replaceMe, hex(i)))
    contract_id, contract_interface = compiled_sol.popitem()
    bytecode = contract_interface['bin']
    actualBytecode = bytecode[556:556 + 199 * 2]
    b = bytes.fromhex(actualBytecode)
    k = sha3.keccak_256()
    k.update(b)
    if (int(k.hexdigest(), 16) & 0xFF000000) >> 0x18 == 199:
        print(int(k.hexdigest(), 16))
        print(bytecode)
        return True
    return False


while True:
    if check(i):
        print("FOUND ID")
        print(hex(i))
        break
    elif i % 0xfffff == 0:
        print(hex(i))
    i += 1
{% endhighlight %}

One more detail - `solcx` doesn't work well with newer solidity versions, so I needed to compile the code with `0.8.9`. The resulting bytecode is given to my solve contract as a parameter, since different compilers might generate slightly different bytecode (because of that metadata).

That's it! This was the hardest part of the challenge - only uphill from here :)

## The Lazyoor

Remeber that there are 2 ways of getting `0xFF` into storage slot `0x1337`:
 * `AAAA` + `BBBB` + `CCCC`
 * `AAAA` + `CCCC` + `DDDD` + `EEEE`

The first one involves fewer function calls, so let's try reversing `BBBB`. Here's the function's wrapper code:

{% highlight python %}
:label16
# Stack: [@0x16E @0x174 @0x16E]
0x20F   PUSH(:label17)
0x212   DUP3
0x216   JUMP(:label2)

:label17
# Stack: [@0x5C @0x16E @0x174 @0x16E]
0x218   DUP1
0x21E   JUMPI(:label18, !!POP(@0x5C))

# Stack: [@0x5C @0x16E @0x174 @0x16E]
0x222   PUSH(SLOAD(0x1337))
0x225   DUP1
0x22A   SSTORE(0x1337, POP(@0x222) ^ 0xD1)
0x22B   POP()
{% endhighlight %}

The value at `0x5C` needs to be false. Let's take a look at `label2`:

{% highlight python %}
:label2
# Stack: [@0x174 :label17 @0x16E @0x174 @0x16E]
0x44    PUSH(0x0)
0x46    DUP1
0x49    MSTORE(0xF, POP(@0x174))
0x4E    PUSH(SHA3(0xF, 0x4))
0x57    DUP1
0x5C    PUSH(!(SHR(0xC8, POP(@0x4E)) == 0xFD28448C97D19C))
0x5D    SWAP2
0x5E    POP()
0x5F    POP()

# Stack: [@0x5C @0x174 :label17 @0x16E @0x174 @0x16E]
0x61    SWAP2
0x62    SWAP1
0x63    POP()
0x64    JUMP(POP(:label17))
{% endhighlight %}

Not too complex now that we've seen `CCCC`, right? The code checks that some bytes of `SHA3(arg1)` are equal to `0xFD28448C97D19C`. Let's just make a quick python script that bruteforces `0xFFFFFFFF` values and we'll be done!

Well, after running that script twice and making sure there are no errors in it, I have to tell you that no 4-byte value can satisfy the constraint. It's impossible, so we'll have to take a look at the other two functions.

## The DDDDoor

To get a sense of this function, let's start with the wrappers, `label22` and `label23`:

{% highlight bash %}
:label22
# Stack: [@0x16E @0x174 @0x16E]
0x257   PUSH(:label23)
0x25A   DUP3
0x25E   JUMP(:label4)

:label23
# Stack: [@0xEE @0x16E @0x174 @0x16E]
0x260   DUP1
0x266   JUMPI(:label24, !!POP(@0xEE))

# Stack: [@0xEE @0x16E @0x174 @0x16E]
0x26A   PUSH(SLOAD(0x1337))
0x26D   DUP1
0x272   SSTORE(0x1337, POP(@0x26A) ^ 0xB2)
0x273   POP()
{% endhighlight %}

THe value at `0xEE` should be false. Here's `label4`:

{% highlight bash %}
:label4
# Stack: [@0x174 :label23 @0x16E @0x174 @0x16E]
0xB6    PUSH(0x0)
0xBC    DUP1
0xC0    PUSH(SHR(0x8, POP(@0x174) & 0xFFFF00))
0xC3    DUP1
0xCA    PUSH(0x2 * (SHL(0x7, POP(@0xC0)) + 0xD))
0xCD    DUP3
0xD5    PUSH(0x101 * (SHR(0x18, POP(@0x174)) & 0xFF))
0xDA    DUP4
0xE5    PUSH(BLOCKHASH(NUMBER() - 0x3 + (0x2 * (POP(@0x174) & 0xFF) & 0xFF)))
0xE6    DUP1
0xE7    DUP4
0xE9    DUP2
0xEE    PUSH(!(0x0 == POP(@0xD5) ^ POP(@0xCA) + POP(@0xE5)))
0xEF    SWAP5
0xF0    POP()
0xF1    POP()
0xF2    POP()
0xF3    POP()
0xF4    POP()

# Stack: [@0xEE @0x174 :label23 @0x16E @0x174 @0x16E]
0xF6    SWAP2
0xF7    SWAP1
0xF8    POP()
0xF9    JUMP(POP(:label23))
{% endhighlight %}

To get the XOR, we need to satisfy the following condition: `0x0 == POP(@0xD5) ^ POP(@0xCA) + POP(@0xE5)`. To better understand the conditions, I will divide the argument passed to this function into 4 1-byte groups and write it as `ABCD`.

`0xE5` is `BLOCKHASH(NUMBER() - 0x3 + (0x2 * (POP(@0x174) & 0xFF) & 0xFF))` - it translates to `BLOCKHASH(NUMBER() - 0x3 + (0x2 * D & 0xFF))`. The `BLOCKHASH` functions returns `0x0` for all 'future' blocks, so a value such as `0x87` should do the job (`number + 14 - 3 = number + 11`, which is in the future).

`0xD5` is `0x101 * (SHR(0x18, POP(@0x174)) & 0xFF)`, which translates to `A * 0x101`. `0xCA` is `0x2 * (SHL(0x7, POP(@0xC0)) + 0xD)`, which could be written as `2 * (SHL(0x7, BC)+ 0xD)`, and `0xC0` is `SHR(0x8, POP(@0x174) & 0xFFFF00)`, which is just `BC`.

To find A, B, and C, we just need to find numbers that satisfy this condition: `A * 0x101 == 2 * (SHL(0x7, BC)+ 0xD)`. So, how could we find the appropriate values for A and BC? Simple - bruteforce! For all values of BC, see if A can be computed. Here's the short python code:

{% highlight python %}
for i in range(0xffff):
 if 2 * ((i << 7) + 0xD) % 0x101 == 0:
  a = 2 * ((i << 7) + 0xD) / 0x101
  if a > 0 and a < 0x100:
   print(i,a) # 26 26.0
{% endhighlight %}

The only values of A and BC for which the statement is true are `26` and `26`. Therefore, the argument for the function needs to be `0x1a001a87`. One more function and we're done!

## The EEEEoor

Let's begin by taking a look at `label25` and `label26`:

{% highlight bash %}
:label25
# Stack: [@0x16E @0x174 @0x16E]
0x27B   PUSH(:label26)
0x27E   DUP3
0x282   JUMP(:label5)

:label26
# Stack: [@0x151 @0x16E @0x174 @0x16E]
0x286   DUP1
0x28C   JUMPI(:label27, !(POP(@0x151) == 0x1))

# Stack: [@0x151 @0x16E @0x174 @0x16E]
0x290   PUSH(SLOAD(0x1337))
0x293   DUP1
0x298   SSTORE(0x1337, POP(@0x290) ^ 0x63)
0x299   POP()

:label27
# Stack: [@0x151 @0x16E @0x174 @0x16E]
0x29B   POP()
0x29F   JUMP(:label31)
{% endhighlight %}

This time, we need to make `0x151` return 1. If we go to `label5`, however, you'll see that the flow is a little bit more complex this time:

{% highlight bash %}
:label5
# Stack: [@0x174 :label26 @0x16E @0x174 @0x16E]
0xFB    PUSH(0x0)
0xFE    PUSH(EXTCODEHASH(ADDRESS()))
0xFF    DUP1
0x102   MSTORE(0x7, POP(@0xFE))
0x103   PUSH(0x0)
0x105   PUSH(0x0)
0x107   PUSH(0x0)

:label6
# Stack: [[@0x13B | 0x0] [0x0 | @0x133] [0x0 | @0x12D] @0xFE 0x0 @0x174 :label26 @0x16E @0x174 @0x16E]
0x10C   DUP1
0x112   JUMPI(:label8, !(POP() < 0x20))

# Stack: [[@0x13B | 0x0] [0x0 | @0x133] [0x0 | @0x12D] @0xFE 0x0 @0x174 :label26 @0x16E @0x174 @0x16E]
0x117   DUP6
0x118   DUP2
0x120   JUMPI(:label7, !(SHR(POP(), POP(@0x174)) & 0x1 == 0x1))

# Stack: [[0x0 | @0x13B] [0x0 | @0x133] [0x0 | @0x12D] @0xFE 0x0 @0x174 :label26 @0x16E @0x174 @0x16E]
0x128   DUP1
0x12C   DUP3
0x12D   PUSH(POP() + (SHR(POP() * 0x8, MLOAD(0x7)) & 0xFF))
0x12E   SWAP3
0x12F   POP()
0x132   DUP2
0x133   PUSH(POP() + 0x1)
0x134   SWAP2
0x135   POP()

:label7
# Stack: [[0x0 | @0x13B] [@0x133 | 0x0] [@0x12D | 0x0] @0xFE 0x0 @0x174 :label26 @0x16E @0x174 @0x16E]
0x13A   DUP1
0x13B   PUSH(POP() + 0x1)
0x13C   SWAP1
0x13D   POP()
0x141   JUMP(:label6)

:label8
# Stack: [[@0x13B | 0x0] [@0x133 | 0x0] [@0x12D | 0x0] @0xFE 0x0 @0x174 :label26 @0x16E @0x174 @0x16E]
0x143   POP()
0x146   DUP1
0x14B   DUP2
0x151   PUSH((0x309 == POP() % 0x539) * (POP() == 0x11))
0x152   SWAP4
0x153   POP()
0x154   POP()
0x155   POP()
0x156   POP()

# Stack: [@0x151 @0x174 :label26 @0x16E @0x174 @0x16E]
0x158   SWAP2
0x159   SWAP1
0x15A   POP()
0x15B   JUMP(POP(:label26))
{% endhighlight %}

At this point, it's just time to take out a pen and draw a schematic of the program. In short, it's a while loop that has 3 variables - say A, B, and C. A starts from 0 and the loop stops when it reaches `0x20`. If the bit at index A of `ARG1` is set to 1, then B will get incremented and a value based on the vault's code hash will be added to C. The target is to get B to equal `0x11` (= 17 bits set to one in `ARG1`) and satisfy the following condition: `C % 0x539 == 0x309`. We could compute these using combinations of the hash bytes and whatnot, but it's easier to just bruteforce a valid parameter:

{% highlight python %}
codehash = 0x6bca38432e686d0a2ab98d1cab5f21998075ffef811b6bb03d52812fa9a8f752

def tryMagicVal(magicVal):
    A = 0
    B = 0
    C = 0
    while A < 0x20:
        if (magicVal >> A) & 1 == 1:
            C += (codehash >> (8 * A)) & 0xff
            B += 1
        A += 1
    return B == 0x11 and C % 0x539 == 0x309

i = 0
while i < 0xffffffff:
    if i % 0xffff == 0:
        print(hex(i))
    if tryMagicVal(i):
        print("FOUND!")
        print(i)
        print(hex(i))
        break
    i += 1
{% endhighlight %}

The first value that satisfies the conditions is `0x000f97ff`, but I'm sure there are many others.

## The Finalizoor

That's it! After calling the 'vrfy' function, the storage slot 'solved' gets set to one! You can find a 2 AM implementation of the solution [here](https://github.com/Yakuhito/DownUnderCTF-2022/blob/master/contracts/EVMVaultUnlocker.sol) (weird implementation because I had to debug it - gas issues!). You can also find the original source code of the contract [here](https://github.com/DownUnderCTF/Challenges_2022_Public/blob/main/blockchain/evm-vault-mechanism/src/chall.yul).

I don't know how you felt when reading this article, but I'm really glad I solved this challenge. I spent a lot of hours on it, but managed to learn Solidity assembly and do a little bit of reverse engineering. It's probably one of my favorite challenges, even though it might seem ordinary if you haven't worked through it yourself.

*now please excuse me but I have to do Minerva stuff*

Until next time, hack the world.

yakuhito, over.