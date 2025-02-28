// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract FileStorage {
    string[] private fileCIDs; // Stores multiple IPFS CIDs

    // Store CID on blockchain
    function storeFileCID(string memory cid) public {
        fileCIDs.push(cid);
    }

    // Retrieve all stored CIDs
    function getStoredCIDs() public view returns (string[] memory) {
        return fileCIDs;
    }
}
