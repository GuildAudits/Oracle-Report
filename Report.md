# [M-01] `roundDifference` Calculation Ignores Pair Direction 

When calculating a derived price (e.g., BTC/ETH from BTC/USD and ETH/USD), it is critical to know if the two underlying prices are synchronized. The roundDifference is designed to be this synchronization check. According to the project's documentation and interface, it must provide two key pieces of information:

Magnitude: How many versions (rounds) apart are the two price feeds?
Direction: Which price feed is newer? This is conveyed by the sign of the result.
The Mismatch: Specification vs. Implementation
There is a direct contradiction between the contract's public-facing promise and its internal logic.

1. The Specification (The Promise)

The `IIfaPriceFeed.sol` interface clearly documents that roundDifference is directional: 
File: oracle_contract-main/src/Interface/IIfaPriceFeed.sol

```solidity
struct DerviedPair {
    // ...
    int256 roundDifference; //  roundDifference = asset0.roundId - asset1.roundId  if Pair direction is Forward  otherwise  roundDifference = asset1.roundId  - asset0.roundId
}
```
This establishes a clear contract: a positive roundDifference means the numerator's price is newer, and a negative value means it's older.

2. The Implementation 

The _getPairInfo function in IfaPriceFeed.sol ignores this specification. It calculates the absolute difference, discarding the directional information. 
File: oracle_contract-main/src/IfaPriceFeed.sol

```solidity
// ...
        int256 roundDifference;
        if (_roundId0 >= _roundId1) {
            roundDifference = int256(_roundId0) - int256(_roundId1);
        } else {
            roundDifference = int256(_roundId1) - int256(_roundId0);
        }
// ...
```
This code block will always produce a positive roundDifference (or zero), regardless of the _direction parameter.

### Impact: 
It completely undermines the security model for any protocol that integrates with this oracle. A consuming protocol (e.g., a lending market) would build its safety checks based on the promise made in the interface.

### Recommendation
The `_getPairInfo` function must be corrected to adhere to its specification. The roundDifference calculation should be moved inside the directional logic. This change also provides an opportunity to improve gas efficiency by reading structs from storage directly instead of making multiple internal function calls.


# [L-01] Lack of Timestamp Equality Check in Batch Price Submissions

### Summary
The submitPriceFeed function in `IfaPriceFeedVerifier.sol` is responsible for processing batch price updates from a trusted relayer. The function lacks a crucial validation to ensure that all price updates within a single batch submission share the same timestamp. This allows a relayer to submit a set of prices that were recorded at different times within a single atomic transaction, which can lead to data inconsistencies and break the assumptions of consuming protocols.

Details
The submitPriceFeed function iterates through the _assetindex and _prices arrays, processing each price update individually. For each update, it checks if the new price's timestamp is more recent than the one currently in storage for that specific asset.

File: oracle_contract-main/src/IfaPriceFeedVerifier.sol
```solidity
 Show full code block 
function submitPriceFeed(uint64[] calldata _assetindex, IIfaPriceFeed.PriceFeed[] calldata _prices)
    external
    onlyRelayerNode
{
    require(_assetindex.length == _prices.length, InvalidAssetIndexorPriceLength());

    for (uint256 i = 0; i < _assetindex.length; i++) {
        uint64 pair = _assetindex[i];
        IIfaPriceFeed.PriceFeed calldata currentPriceFeed = _prices[i];
        uint256 currenttimestamp = currentPriceFeed.lastUpdateTime;
        (IIfaPriceFeed.PriceFeed memory prevPriceFeed,) = IfaPriceFeed.getAssetInfo(pair);
        if (prevPriceFeed.lastUpdateTime > currenttimestamp) {
            continue; // Skips stale data for an individual asset
        }

        IfaPriceFeed.setAssetInfo(pair, currentPriceFeed);
    }
}
```
The issue is that there is no check to enforce that `_prices[0].lastUpdateTime` is equal to `_prices[1].lastUpdateTime`, and so on for all elements in the batch.

Impact
The atomicity of a batch update implies that all data within it represents a snapshot from the same point in time. By allowing different timestamps, this core assumption is violated.

### Recommendation
It is highly recommended to enforce timestamp consistency for all price feeds submitted in a single batch. This can be achieved by checking that all lastUpdateTime values in the _prices array are identical. This ensures that each batch submission represents a coherent and reliable snapshot of market prices.


# [L-02] Self-Pairing Allowed in Price Calculation
## Summary
The internal function _getPairInfo, which is used by all public-facing pair-fetching functions (getPairbyId, getPairsbyIdForward, etc.), does not validate that the two asset indexes provided (_assetIndex0 and _assetIndex1) are different. This allows a caller to request the price for a pair of the same asset (e.g., BTC/BTC). The function will not revert but will return a derived price of exactly 1.0, which could lead to unexpected behavior or manipulation in protocols that consume this oracle data.

The `_getPairInfo` function in `IfaPriceFeed.sol` is the core logic for calculating derived exchange rates. It accepts two asset indexes but lacks a check to ensure they are not identical.

File: oracle_contract-main/src/IfaPriceFeed.sol

```solidity
 Show full code block 
function _getPairInfo(uint64 _assetIndex0, uint64 _assetIndex1, PairDirection _direction)
    internal
    view
    returns (DerviedPair memory pairInfo)
{
    // No check to ensure _assetIndex0 != _assetIndex1
    (PriceFeed memory _assetInfo0, bool exist0) = _getAssetInfo(_assetIndex0);
    (PriceFeed memory _assetInfo1, bool exist1) = _getAssetInfo(_assetIndex1);
    // ...
}
```
When `_assetIndex0` is the same as `_assetIndex1`, the function will fetch the same price data for both assets. The subsequent calculation will result in:

derivedPrice: 1 * 10**18 (representing a price of 1.0)
roundDifference: 0
lastUpdateTime: The timestamp of that single asset.

### Impact

While not a direct exploit, it opens a potential attack vector. If a consuming protocol has a vulnerability that is triggered by a price of exactly 1.0 and a roundDifference of 0, an attacker could use this behavior to their advantage. For example, a flawed rewards or fee mechanism might behave differently for trades at a 1:1 ratio.
It is also logically inconsistent for a price feed oracle to provide a derived price for an asset against itself. This indicates a lack of robustness in handling edge cases.

## Recommendation
It is recommended to add a validation check at the beginning of the _getPairInfo function to ensure the two asset indexes are not the same. This makes the function's behavior more robust, predictable, and secure.


# [L-03] Lack of Zero-Price Validation in Price Submissions
## Summary
The `submitPriceFeed` function in `IfaPriceFeedVerifier.sol` does not validate that submitted prices are greater than zero. The relayer could provide a price of 0 for an asset, which would be accepted and stored on-chain. This creates a Denial of Service (DoS) vulnerability for any function that attempts to calculate a derived pair where the zero-priced asset is the denominator, as it will lead to a division-by-zero error.

Details
The `submitPriceFeed` function is the entry point for all new price data. While it checks for stale data using `lastUpdateTime`, it completely omits a check to ensure the price field itself is a valid, non-zero number.

File: oracle_contract-main/src/IfaPriceFeedVerifier.sol

```solidity
function submitPriceFeed(uint64[] calldata _assetindex, IIfaPriceFeed.PriceFeed[] calldata _prices)
    external
    onlyRelayerNode
{
    require(_assetindex.length == _prices.length, InvalidAssetIndexorPriceLength());

    for (uint256 i = 0; i < _assetindex.length; i++) {
        uint64 pair = _assetindex[i];
        IIfaPriceFeed.PriceFeed calldata currentPriceFeed = _prices[i];
        // Lacks a check: require(currentPriceFeed.price > 0);
>>      uint256 currenttimestamp = currentPriceFeed.lastUpdateTime;
        (IIfaPriceFeed.PriceFeed memory prevPriceFeed,) = IfaPriceFeed.getAssetInfo(pair);
        if (prevPriceFeed.lastUpdateTime > currenttimestamp) {
            continue;
        }

        IfaPriceFeed.setAssetInfo(pair, currentPriceFeed);
    }
}
```
### Impact

If an asset's price is updated to 0, any call to getPairbyId or related functions where this asset is the denominator will fail. The `_getPairInfo` function uses `FixedPointMathLib.mulDiv`, which correctly reverts on division by zero. This will cause transactions to fail, potentially halting critical operations like liquidations, swaps, or borrowing in dependent DeFi protocols.

### Recommendation
It is essential to add a strict validation check in submitPriceFeed to ensure that all submitted prices are greater than zero. This can be implemented by adding a require statement and a corresponding custom error for clarity.


# [L-04] Incomplete Stale Price Check in submitPriceFeed
### Summary
The submitPriceFeed function in IfaPriceFeedVerifier.sol lacks a crucial "liveness" check to ensure that submitted price data is recent relative to the current block time. The existing check only prevents overwriting a newer on-chain price with an older one, but it does not prevent a relayer from submitting significantly outdated prices. This allows stale data to enter the system, posing a significant risk to any protocol that relies on the oracle for timely price information.


File: oracle_contract-main/src/IfaPriceFeedVerifier.sol

```solidity

(IIfaPriceFeed.PriceFeed memory prevPriceFeed,) = IfaPriceFeed.getAssetInfo(pair);
if (prevPriceFeed.lastUpdateTime > currenttimestamp) {
    continue; // Skips if the submitted price is older than the on-chain price
}
// ...
```
While this check is useful, it is insufficient. It does not validate the freshness of the submitted price against the current network time (block.timestamp). 

### Impact
This vulnerability allows a relayer to report old prices, which is especially dangerous during periods of high market volatility. Protocols consuming this oracle data could be fed stale, inaccurate prices.

## Recommendation
It is critical to implement a strict liveness check by validating the submitted timestamp against the current block timestamp. This can be achieved by introducing a configurable maxStalePeriod that defines the maximum acceptable age of a price feed. The owner should be able to set this period.

# [L-05] Indexing a Struct Provides No Searchable Value and Increases Gas Costs
### Summary
The AssetInfoSet event, defined in the IIfaPriceFeed.sol interface, incorrectly marks the PriceFeed struct as indexed. In Solidity, indexing a struct does not make its individual fields searchable. Instead, the entire struct is ABI-encoded and hashed, and this single bytes2 hash is stored as the indexed topic. This is not useful for off-chain filtering, misleads developers about the event's capabilities, and unnecessarily increases the gas cost of every price update.

The event is defined in the interface as follows:

File: /src/Interface/IIfaPriceFeed.sol

```solidity
event AssetInfoSet(uint64 indexed _assetIndex, PriceFeed indexed assetInfo);
```
When an event parameter of a complex type (like a struct or array) is marked as indexed, Solidity computes the keccak256 hash of its ABI-encoded representation and stores that hash as the topic.

This means that an off-chain service trying to filter for these events would see a topic like 0x123...abc for the assetInfo. To find a specific event, the service would need to know the exact contents of the PriceFeed struct (decimal, lastUpdateTime, price, and roundId) to reconstruct the hash and search for it. This defeats the purpose of filtering, which is to find events based on variable criteria (e.g., "find all price updates where the price was above $50,000").

### Impact

The indexed keyword on the struct parameter suggests a search capability that does not exist. This can lead to incorrect assumptions and wasted effort by developers who try to build services that rely on filtering these events by their content.

## Recommendation
To resolve this, the indexed keyword should be removed from the assetInfo parameter in the event definition. The full struct data will still be available in the non-indexed (data) portion of the event log, where it can be easily decoded and accessed by off-chain services. This change will reduce gas costs and make the event's capabilities clear and unambiguous.

# [I-01] Incorrect Error Reporting in Batch Pair Functions

### Summary
The `getPairsbyIdForward`, `getPairsbyIdBackward`, and `getPairsbyId` functions in `IfaPriceFeed.sol` provide incorrect details when they revert due to mismatched input array lengths. The custom errors are populated with the length of the first array for both length arguments, which hides the actual mismatched length of the second array from the caller and complicates debugging.

Details
The contract includes several functions for fetching multiple pair prices in a single call. These functions correctly validate that the input arrays `(_assetIndexes0, _assetsIndexes1, and sometimes _direction)` have equal lengths. However, when this check fails, the arguments passed to the custom error are incorrect.

`getPairsbyIdForward` and `getPairsbyIdBackward`

These functions use the InvalidAssetIndexLength error, which is defined to accept two uint256 parameters: the length of the first array and the length of the second. The implementation incorrectly passes _assetIndexes0.length for both.

File: oracle_contract-main/src/IfaPriceFeed.sol

```solidity
// Incorrect implementation in getPairsbyIdForward
require(
    _assetIndexes0.length == _assetsIndexes1.length,
    InvalidAssetIndexLength(_assetIndexes0.length, _assetIndexes0.length) // Should be _assetsIndexes1.length
);
```
`getPairsbyId`

This function has a similar issue with the InvalidAssetorDirectionIndexLength error. It passes _assetIndexes0.length as the value for the second asset array's length instead of the correct _assetsIndexes1.length.

File: oracle_contract-main/src/IfaPriceFeed.sol

```solidity
// Incorrect implementation in getPairsbyId
require(
    _assetIndexes0.length == _assetsIndexes1.length && _assetIndexes0.length == _direction.length,
    InvalidAssetorDirectionIndexLength(_assetIndexes0.length, _assetIndexes0.length, _direction.length) // Should be _assetsIndexes1.length
);
```
### Impact
When a developer calls one of these functions with mismatched array lengths, the revert message will be misleading. For example, if `_assetIndexes0` has a length of 5 and `_assetsIndexes1` has a length of 4, the error will report the lengths as (5, 5) instead of the correct (5, 4). This makes it significantly harder for developers to debug their integration, as the error message does not accurately reflect the state that caused the transaction to fail.

## Recommendation
The arguments passed to the custom errors should be corrected to reflect the actual lengths of the input arrays. This provides accurate and helpful debugging information to the caller.


# [I-02] Unnecessary Comments and Inefficient Logic in _getAssetInfo
## Summary
The `_getAssetInfo` function in `IfaPriceFeed.sol` contains commented-out code and non-standard comments that reduce code clarity. Furthermore, the function's logic is inefficient as it can result in reading the same storage slot multiple times.


File: oracle_contract-main/src/IfaPriceFeed.sol

```solidity
//require(_assetInfo[_assetIndex].lastUpdateTime > 0, InvalidAssetIndex(_assetIndex));
//...
```

Impact
This is an informational finding. While there is no direct security vulnerability, the issues affect code quality. The unnecessary comments make the code harder to read and maintain.

Recommendation
It is recommended to refactor the _getAssetInfo function to remove the comments and optimize the logic. 
