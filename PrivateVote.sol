// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {
    FHE,
    euint32,
    euint64,
    ebool,
    InEuint32,
    eaddress
} from "@fhenixprotocol/cofhe-contracts/FHE.sol";

/// @title PrivateVote
/// @notice Fully encrypted on-chain voting using FHE
/// @dev Vote tallies are encrypted throughout the voting period.
///      No one — not even the contract owner — can see partial results.
///      Results are only revealed after the voting period ends.
contract PrivateVote {

    // ============ Enums ============

    enum ProposalStatus {
        Active,
        Ended,
        ResultRequested,
        ResultRevealed,
        Cancelled
    }

    // ============ Structs ============

    struct Proposal {
        string title;
        string description;
        address creator;
        uint256 startTime;
        uint256 endTime;
        ProposalStatus status;
        uint8 optionCount;      // 2–4 options
        string[4] options;      // option labels
        // Encrypted vote counts (one per option, max 4)
        euint32 votes0;
        euint32 votes1;
        euint32 votes2;
        euint32 votes3;
        // Decrypted results (available after reveal)
        uint32 result0;
        uint32 result1;
        uint32 result2;
        uint32 result3;
        // Ciphertext hashes for frontend decryption
        bytes32 ctHash0;
        bytes32 ctHash1;
        bytes32 ctHash2;
        bytes32 ctHash3;
        // Tracking
        uint256 totalVotes;
        bool hasQuorum;
        uint256 quorumThreshold;
    }

    struct ProposalView {
        uint256 id;
        string title;
        string description;
        address creator;
        uint256 startTime;
        uint256 endTime;
        ProposalStatus status;
        uint8 optionCount;
        string[4] options;
        uint256 totalVotes;
        bool hasQuorum;
        uint256 quorumThreshold;
    }

    // ============ State ============

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    mapping(address => uint256[]) public voterHistory;
    mapping(address => uint256[]) public creatorProposals;

    uint256 public nextProposalId;
    uint256 public totalProposals;

    // ============ Events ============

    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed creator,
        string title,
        uint256 startTime,
        uint256 endTime,
        uint8 optionCount
    );

    event VoteCast(
        uint256 indexed proposalId,
        address indexed voter,
        uint256 timestamp
    );

    event ResultRequested(
        uint256 indexed proposalId,
        bytes32 ctHash0,
        bytes32 ctHash1,
        bytes32 ctHash2,
        bytes32 ctHash3
    );

    event ResultRevealed(
        uint256 indexed proposalId,
        uint32 votes0,
        uint32 votes1,
        uint32 votes2,
        uint32 votes3,
        uint8 winningOption
    );

    event ProposalCancelled(uint256 indexed proposalId);

    // ============ Errors ============

    error ProposalNotActive();
    error ProposalNotEnded();
    error AlreadyVoted();
    error InvalidOptionCount();
    error InvalidOption();
    error InvalidTimeRange();
    error TitleRequired();
    error TitleTooLong();
    error DescriptionTooLong();
    error NotCreator();
    error ResultNotRequested();
    error HasVoters();
    error InvalidDecryptionProof();
    error ResultAlreadyRevealed();

    // ============ Create ============

    /// @notice Create a new private vote proposal
    /// @param title Proposal title (max 64 chars)
    /// @param description Proposal description (max 512 chars)
    /// @param optionCount Number of voting options (2-4)
    /// @param options Array of option labels
    /// @param startTime Unix timestamp for vote start
    /// @param endTime Unix timestamp for vote end
    /// @param quorumThreshold Minimum votes required for valid result (0 = no quorum)
    function createProposal(
        string calldata title,
        string calldata description,
        uint8 optionCount,
        string[4] calldata options,
        uint256 startTime,
        uint256 endTime,
        uint256 quorumThreshold
    ) external returns (uint256 proposalId) {
        if (bytes(title).length == 0) revert TitleRequired();
        if (bytes(title).length > 64) revert TitleTooLong();
        if (bytes(description).length > 512) revert DescriptionTooLong();
        if (optionCount < 2 || optionCount > 4) revert InvalidOptionCount();
        if (endTime <= startTime) revert InvalidTimeRange();
        if (startTime < block.timestamp) revert InvalidTimeRange();

        proposalId = nextProposalId++;
        totalProposals++;

        Proposal storage p = proposals[proposalId];
        p.title = title;
        p.description = description;
        p.creator = msg.sender;
        p.startTime = startTime;
        p.endTime = endTime;
        p.status = ProposalStatus.Active;
        p.optionCount = optionCount;
        p.options = options;
        p.quorumThreshold = quorumThreshold;

        // Initialize encrypted vote counts at 0
        p.votes0 = FHE.asEuint32(0);
        p.votes1 = FHE.asEuint32(0);
        p.votes2 = FHE.asEuint32(0);
        p.votes3 = FHE.asEuint32(0);

        // Grant this contract ACL on the encrypted counters
        FHE.allowThis(p.votes0);
        FHE.allowThis(p.votes1);
        FHE.allowThis(p.votes2);
        FHE.allowThis(p.votes3);

        creatorProposals[msg.sender].push(proposalId);

        emit ProposalCreated(
            proposalId, msg.sender, title, startTime, endTime, optionCount
        );
    }

    // ============ Vote ============

    /// @notice Cast an encrypted vote
    /// @dev The voter encrypts their choice off-chain using CoFHE SDK.
    ///      On-chain, FHE select() adds 1 to exactly one counter without
    ///      revealing which option was chosen.
    /// @param proposalId The proposal to vote on
    /// @param encryptedChoice Encrypted choice index (0, 1, 2, or 3)
    function vote(
        uint256 proposalId,
        InEuint32 calldata encryptedChoice
    ) external {
        Proposal storage p = proposals[proposalId];

        if (p.status != ProposalStatus.Active) revert ProposalNotActive();
        if (block.timestamp < p.startTime) revert ProposalNotActive();
        if (block.timestamp >= p.endTime) revert ProposalNotActive();
        if (hasVoted[proposalId][msg.sender]) revert AlreadyVoted();

        hasVoted[proposalId][msg.sender] = true;
        voterHistory[msg.sender].push(proposalId);
        p.totalVotes++;

        // Decrypt the choice index to compare (encrypted 0/1/2/3)
        euint32 choice = FHE.asEuint32(encryptedChoice);
        FHE.allowThis(choice);

        // For each option, compute: isThisOption = (choice == optionIndex)
        // Then conditionally add 1 to that option's counter
        // This reveals nothing about which option was chosen

        euint32 one = FHE.asEuint32(1);
        FHE.allowThis(one);

        // Option 0
        ebool isOpt0 = FHE.eq(choice, FHE.asEuint32(0));
        p.votes0 = FHE.add(p.votes0, FHE.select(isOpt0, one, FHE.asEuint32(0)));
        FHE.allowThis(p.votes0);

        // Option 1
        ebool isOpt1 = FHE.eq(choice, FHE.asEuint32(1));
        p.votes1 = FHE.add(p.votes1, FHE.select(isOpt1, one, FHE.asEuint32(0)));
        FHE.allowThis(p.votes1);

        // Option 2 (only relevant if optionCount >= 3)
        ebool isOpt2 = FHE.eq(choice, FHE.asEuint32(2));
        p.votes2 = FHE.add(p.votes2, FHE.select(isOpt2, one, FHE.asEuint32(0)));
        FHE.allowThis(p.votes2);

        // Option 3 (only relevant if optionCount == 4)
        ebool isOpt3 = FHE.eq(choice, FHE.asEuint32(3));
        p.votes3 = FHE.add(p.votes3, FHE.select(isOpt3, one, FHE.asEuint32(0)));
        FHE.allowThis(p.votes3);

        emit VoteCast(proposalId, msg.sender, block.timestamp);
    }

    // ============ Settlement ============

    /// @notice Request result reveal — marks encrypted tallies for decryption
    /// @dev Anyone can call this after voting ends
    function requestResult(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];

        if (p.status != ProposalStatus.Active) revert ProposalNotActive();
        if (block.timestamp < p.endTime) revert ProposalNotEnded();

        p.status = ProposalStatus.ResultRequested;

        // Allow public decryption via Threshold Network
        FHE.allowPublic(p.votes0);
        FHE.allowPublic(p.votes1);
        FHE.allowPublic(p.votes2);
        FHE.allowPublic(p.votes3);

        // Capture ctHashes for frontend
        p.ctHash0 = euint32.unwrap(p.votes0);
        p.ctHash1 = euint32.unwrap(p.votes1);
        p.ctHash2 = euint32.unwrap(p.votes2);
        p.ctHash3 = euint32.unwrap(p.votes3);

        emit ResultRequested(proposalId, p.ctHash0, p.ctHash1, p.ctHash2, p.ctHash3);
    }

    /// @notice Finalize result with decrypted values and proofs from Threshold Network
    function finalizeResult(
        uint256 proposalId,
        uint32 votes0,
        uint32 votes1,
        uint32 votes2,
        uint32 votes3,
        bytes calldata proof0,
        bytes calldata proof1,
        bytes calldata proof2,
        bytes calldata proof3
    ) external {
        Proposal storage p = proposals[proposalId];

        if (p.status != ProposalStatus.ResultRequested) revert ResultNotRequested();
        if (p.status == ProposalStatus.ResultRevealed) revert ResultAlreadyRevealed();

        // Verify Threshold Network proofs
        if (!FHE.verifyDecryptResult(p.votes0, votes0, proof0)) revert InvalidDecryptionProof();
        if (!FHE.verifyDecryptResult(p.votes1, votes1, proof1)) revert InvalidDecryptionProof();
        if (!FHE.verifyDecryptResult(p.votes2, votes2, proof2)) revert InvalidDecryptionProof();
        if (!FHE.verifyDecryptResult(p.votes3, votes3, proof3)) revert InvalidDecryptionProof();

        p.result0 = votes0;
        p.result1 = votes1;
        p.result2 = votes2;
        p.result3 = votes3;
        p.status = ProposalStatus.ResultRevealed;

        // Check quorum
        uint256 total = votes0 + votes1 + votes2 + votes3;
        p.hasQuorum = (p.quorumThreshold == 0 || total >= p.quorumThreshold);

        // Find winning option
        uint8 winner = 0;
        uint32 maxVotes = votes0;
        if (votes1 > maxVotes) { maxVotes = votes1; winner = 1; }
        if (p.optionCount >= 3 && votes2 > maxVotes) { maxVotes = votes2; winner = 2; }
        if (p.optionCount == 4 && votes3 > maxVotes) { winner = 3; }

        emit ResultRevealed(proposalId, votes0, votes1, votes2, votes3, winner);
    }

    // ============ Cancel ============

    function cancelProposal(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        if (msg.sender != p.creator) revert NotCreator();
        if (p.status != ProposalStatus.Active) revert ProposalNotActive();
        if (p.totalVotes > 0) revert HasVoters();

        p.status = ProposalStatus.Cancelled;
        emit ProposalCancelled(proposalId);
    }

    // ============ Views ============

    function getProposal(uint256 proposalId) external view returns (ProposalView memory) {
        Proposal storage p = proposals[proposalId];
        return ProposalView({
            id: proposalId,
            title: p.title,
            description: p.description,
            creator: p.creator,
            startTime: p.startTime,
            endTime: p.endTime,
            status: p.status,
            optionCount: p.optionCount,
            options: p.options,
            totalVotes: p.totalVotes,
            hasQuorum: p.hasQuorum,
            quorumThreshold: p.quorumThreshold
        });
    }

    function getResult(uint256 proposalId) external view returns (
        uint32 v0, uint32 v1, uint32 v2, uint32 v3, bool hasQuorum
    ) {
        Proposal storage p = proposals[proposalId];
        if (p.status != ProposalStatus.ResultRevealed) revert ResultNotRequested();
        return (p.result0, p.result1, p.result2, p.result3, p.hasQuorum);
    }

    function getCtHashes(uint256 proposalId) external view returns (
        bytes32 ct0, bytes32 ct1, bytes32 ct2, bytes32 ct3
    ) {
        Proposal storage p = proposals[proposalId];
        return (p.ctHash0, p.ctHash1, p.ctHash2, p.ctHash3);
    }

    function getCreatorProposals(address creator) external view returns (uint256[] memory) {
        return creatorProposals[creator];
    }

    function getVoterHistory(address voter) external view returns (uint256[] memory) {
        return voterHistory[voter];
    }

    function hasVotedOn(uint256 proposalId, address voter) external view returns (bool) {
        return hasVoted[proposalId][voter];
    }
}
