//
//  HDWallet.swift
//  BitcoinKit
//
//  Created by Kishikawa Katsumi on 2018/02/13.
//  Copyright © 2018 Kishikawa Katsumi. All rights reserved.
//

import Foundation

public final class HDWallet {
    public let network: Network

    public var transactions: [Transaction] {
        return []
    }

    public var unspentTransactions: [Transaction] {
        return []
    }

    public var balance: UInt64 {
        return 0
    }

    private let seed: Data
    private let keychain: HDKeychain

    public enum BIP: UInt32 {
        case fortyFour = 44
        case fortyNine = 49
        case eightyFour = 84
    }
    
    var purpose: UInt32
    private let coinType: UInt32
    var account: UInt32
    var externalIndex: UInt32
    var internalIndex: UInt32

    public init(seed: Data, network: Network) {
        self.seed = seed
        self.network = network
        keychain = HDKeychain(seed: seed, network: network)

        // m / purpose' / coin_type' / account' / change / address_index
        //
        // Purpose is a constant set to 44' (or 0x8000002C) following the BIP43 recommendation.
        // It indicates that the subtree of this node is used according to this specification.
        // Hardened derivation is used at this level.
        purpose = 49

        // One master node (seed) can be used for unlimited number of independent cryptocoins such as Bitcoin, Litecoin or Namecoin. However, sharing the same space for various cryptocoins has some disadvantages.
        // This level creates a separate subtree for every cryptocoin, avoiding reusing addresses across cryptocoins and improving privacy issues.
        // Coin type is a constant, set for each cryptocoin. Cryptocoin developers may ask for registering unused number for their project.
        // The list of already allocated coin types is in the chapter "Registered coin types" below.
        // Hardened derivation is used at this level.
        coinType = network == .mainnet ? 0 : 1

        // This level splits the key space into independent user identities, so the wallet never mixes the coins across different accounts.
        // Users can use these accounts to organize the funds in the same fashion as bank accounts; for donation purposes (where all addresses are considered public), for saving purposes, for common expenses etc.
        // Accounts are numbered from index 0 in sequentially increasing manner. This number is used as child index in BIP32 derivation.
        // Hardened derivation is used at this level.
        // Software should prevent a creation of an account if a previous account does not have a transaction history (meaning none of its addresses have been used before).
        // Software needs to discover all used accounts after importing the seed from an external source. Such an algorithm is described in "Account discovery" chapter.
        account = 0

        // Constant 0 is used for external chain and constant 1 for internal chain (also known as change addresses).
        // External chain is used for addresses that are meant to be visible outside of the wallet (e.g. for receiving payments).
        // Internal chain is used for addresses which are not meant to be visible outside of the wallet and is used for return transaction change.
        // Public derivation is used at this level.

        // Addresses are numbered from index 0 in sequentially increasing manner. This number is used as child index in BIP32 derivation.
        // Public derivation is used at this level.
        externalIndex = 0
        internalIndex = 0
    }

    public func receiveAddress(bip: BIP) throws -> Address {
        return Address(try publicKey(bip: bip))
    }

    public func receiveAddress(bip: BIP, index: UInt32) throws -> Address {
        return Address(try publicKey(bip: bip, index: index))
    }

    public func changeAddress(bip: BIP) throws -> Address {
        return try changeAddress(bip: bip, index: internalIndex)
    }

    public func changeAddress(bip: BIP, index: UInt32) throws -> Address {
        purpose = bip.rawValue
        let privateKey = try keychain.derivedKey(path: "m/\(purpose)'/\(coinType)'/\(account)'/\(Chain.internal.rawValue)/\(index)")
        return Address(privateKey.publicKey())
    }

    public func privateKey(bip: BIP) throws -> HDPrivateKey {
        return try privateKey(bip: bip, index: externalIndex)
    }

    public func publicKey(bip: BIP) throws -> HDPublicKey {
        return try publicKey(bip: bip, index: externalIndex)
    }

    public func privateKey(bip: BIP, index: UInt32) throws -> HDPrivateKey {
        purpose = bip.rawValue
        let privateKey = try keychain.derivedKey(path: "m/\(purpose)'/\(coinType)'/\(account)'/\(Chain.external.rawValue)/\(index)")
        return privateKey
    }

    public func publicKey(bip: BIP, index: UInt32) throws -> HDPublicKey {
        return try privateKey(bip: bip, index: index).publicKey()
    }
    
    public func accountPrivateKey(bip: BIP) throws -> HDPrivateKey {
        purpose = bip.rawValue
        let privateKey = try keychain.derivedKey(path: "m/\(purpose)'/\(coinType)'/\(account)'/")
        return privateKey
    }
    
    public func accountPublicKey(bip: BIP) throws -> HDPublicKey {
        return try accountPrivateKey(bip: bip).publicKey()
    }

    enum Chain : Int {
        case external
        case `internal`
    }
}
