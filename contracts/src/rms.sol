// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./brevis/BrevisApp.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title RiskManagementSystem
 * @dev Enhanced risk management system for DeFi lending with advanced trust scoring
 * @author PsychoPunkSage
 */
contract RiskManagementSystem is
    ReentrancyGuard,
    Pausable,
    AccessControl,
    BrevisApp
{
    bytes32 public constant RISK_MANAGER_ROLE = keccak256("RISK_MANAGER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /////////////
    // STRUCTS //
    /////////////
    struct Loan {
        uint256 loanId;
        uint256 amount;
        uint256 dueDate;
        address borrower;
        LoanStatus status;
        uint256 collateral;
        uint256 interestRate;
        uint256 repaymentDate;
        uint256 latePaymentFee;
        uint256 lastUpdateTimestamp;
    }

    struct UserProfile {
        address user;
        bool isBlacklisted;
        uint256 trustScore;
        uint256 totalRepaid;
        uint256 defaultCount;
        uint256 totalBorrowed;
        uint256 latePaymentCount;
        uint256 lastLoanTimestamp;
        uint256 onTimePaymentCount;
        uint256 totalCollateralLocked;
    }

    enum LoanStatus {
        ACTIVE,
        REPAID,
        DEFAULTED,
        LIQUIDATED
    }

    ///////////////
    // Constants //
    ///////////////
    uint256 public constant BASE_TRUST_SCORE = 100;
    uint256 public constant MIN_TRUST_SCORE = 0;
    uint256 public constant MAX_TRUST_SCORE = 1000;
    uint256 public constant DAILY_LATE_FEE_PERCENTAGE = 1; // 1% per day
    uint256 public constant GRACE_PERIOD_DAYS = 3;
    uint256 public constant MAX_LOAN_DURATION = 365 days;
    uint256 public constant MIN_LOAN_AMOUNT = 0.1 ether;
    uint256 public constant MAX_LOAN_AMOUNT = 10 ether;

    /////////////////////
    // State variables //
    /////////////////////
    bytes32 public vkHash;
    uint256 public loanCounter;
    uint256 public totalActiveLoanValue;
    uint256 public platformFeePercentage;

    mapping(uint256 => Loan) public loans;
    mapping(address => UserProfile) public users;
    mapping(address => uint256[]) public userLoans;
    mapping(address => uint256) public userCollateralBalance;

    ////////////
    // Events //
    ////////////
    event LoanIssued(
        uint256 indexed loanId,
        address indexed borrower,
        uint256 amount,
        uint256 interestRate,
        uint256 collateral,
        uint256 dueDate
    );
    event LoanRepaid(
        uint256 indexed loanId,
        address indexed borrower,
        uint256 amount,
        uint256 latePaymentFee,
        uint256 newTrustScore
    );
    event DefaultRecorded(
        address indexed borrower,
        uint256 indexed loanId,
        uint256 defaultCount,
        uint256 newTrustScore
    );
    event TrustScoreUpdated(
        address indexed user,
        uint256 oldScore,
        uint256 newScore,
        string reason
    );
    event CollateralDeposited(
        address indexed user,
        uint256 amount,
        uint256 newBalance
    );
    event CollateralWithdrawn(
        address indexed user,
        uint256 amount,
        uint256 newBalance
    );
    event UserBlacklisted(address indexed user, string reason);
    event LoanLiquidated(uint256 indexed loanId, address indexed borrower);

    ///////////////
    // Modifiers //
    ///////////////
    modifier onlyValidUser(address _user) {
        require(_user != address(0), "Invalid user address");
        require(!users[_user].isBlacklisted, "User is blacklisted");
        _;
    }

    modifier onlyValidLoan(uint256 _loanId) {
        require(loans[_loanId].loanId == _loanId, "Loan does not exist");
        _;
    }

    modifier withinLoanLimits(uint256 _amount) {
        require(_amount >= MIN_LOAN_AMOUNT, "Loan amount too small");
        require(_amount <= MAX_LOAN_AMOUNT, "Loan amount too large");
        _;
    }

    /////////////////
    // Constructor //
    /////////////////
    constructor(address brevisProof) BrevisApp(IBrevisProof(brevisProof)) {
        grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        grantRole(RISK_MANAGER_ROLE, msg.sender);
        grantRole(ADMIN_ROLE, msg.sender);
        platformFeePercentage = 1; // 1% platform fee
    }

    /**
     * @notice Handle proof results from Brevis verification
     * @dev Processes historical blockchain data to enhance risk assessment
     * @param _vkHash The verification key hash
     * @param _circuitOutput The output from the ZK circuit
     * FOR BREVIS
     */
    function handleProofResult(
        bytes32 /*_requestId */,
        bytes32 _vkHash,
        bytes calldata _circuitOutput
    ) internal override {
        require(vkHash == _vkHash, "Invalid verification key");

        // Decode the circuit output containing historical lending data
        (
            address user,
            uint256 historicalTransactionCount,
            uint256 avgTransactionValue,
            uint256 previousLoanCount,
            uint256 defaultRate,
            uint64 accountAge
        ) = decodeOutput(_circuitOutput);

        UserProfile storage profile = users[user];
        uint256 oldScore = profile.trustScore;

        // Calculate new trust score based on historical data
        uint256 newTrustScore = calculateHistoricalTrustScore(
            historicalTransactionCount,
            avgTransactionValue,
            previousLoanCount,
            defaultRate,
            accountAge
        );

        // Update user profile with historically verified data
        profile.trustScore = newTrustScore;

        emit TrustScoreUpdated(
            user,
            oldScore,
            newTrustScore,
            "Historical data verification via Brevis"
        );
    }

    /**
     * @notice Decode the output from the Brevis circuit
     * @dev Extracts historical blockchain data components
     * @param o The circuit output bytes
     * @return user The user address
     * @return historicalTransactionCount Number of relevant historical transactions
     * @return avgTransactionValue Average value of historical transactions
     * @return previousLoanCount Number of previous loans across protocols
     * @return defaultRate Historical default rate (scaled by 1e18)
     * @return accountAge Age of the account in blocks
     * FOR BREVIS
     */
    function decodeOutput(
        bytes calldata o
    )
        internal
        pure
        returns (
            address user,
            uint256 historicalTransactionCount,
            uint256 avgTransactionValue,
            uint256 previousLoanCount,
            uint256 defaultRate,
            uint64 accountAge
        )
    {
        // Decode user address (20 bytes)
        user = address(bytes20(o[0:20]));

        // Decode historical transaction count (32 bytes)
        historicalTransactionCount = uint256(bytes32(o[20:52]));

        // Decode average transaction value (32 bytes)
        avgTransactionValue = uint256(bytes32(o[52:84]));

        // Decode previous loan count (32 bytes)
        previousLoanCount = uint256(bytes32(o[84:116]));

        // Decode default rate (32 bytes)
        defaultRate = uint256(bytes32(o[116:148]));

        // Decode account age (8 bytes)
        accountAge = uint64(bytes8(o[148:156]));
    }

    /**
     * @notice Calculate trust score based on historical blockchain data
     * @param historicalTransactionCount Number of relevant historical transactions
     * @param avgTransactionValue Average value of historical transactions
     * @param previousLoanCount Number of previous loans across protocols
     * @param defaultRate Historical default rate (scaled by 1e18)
     * @param accountAge Age of the account in blocks
     * @return Updated trust score based on historical data
     */
    function calculateHistoricalTrustScore(
        uint256 historicalTransactionCount,
        uint256 avgTransactionValue,
        uint256 previousLoanCount,
        uint256 defaultRate,
        uint64 accountAge
    ) internal pure returns (uint256) {
        uint256 baseScore = 500; // Start with middle score

        // Account age factor (max 100 points)
        uint256 ageFactor = min((accountAge / 100000) * 10, 100);
        baseScore += ageFactor;

        // Transaction history factor (max 100 points)
        uint256 txFactor = min((historicalTransactionCount / 100) * 10, 100);
        baseScore += txFactor;

        // Average transaction value factor (max 100 points)
        uint256 valueFactor = min((avgTransactionValue / 1 ether) * 5, 100);
        baseScore += valueFactor;

        // Loan history factor (max 100 points)
        uint256 loanFactor = min((previousLoanCount * 10), 100);
        baseScore += loanFactor;

        // Default rate penalty (up to -400 points)
        uint256 defaultPenalty = min((defaultRate * 400) / 1e18, 400);
        if (baseScore > defaultPenalty) {
            baseScore -= defaultPenalty;
        } else {
            baseScore = MIN_TRUST_SCORE;
        }

        return min(baseScore, MAX_TRUST_SCORE);
    }

    function setVkHash(bytes32 _vkHash) external onlyRole(ADMIN_ROLE) {
        vkHash = _vkHash;
    }

    /**
     * @notice Issue a loan to a borrower
     * @param _borrower The address of the borrower
     * @param _amount The amount of the loan
     * @param _interestRate The interest rate for the loan
     * @param _collateral The collateral amount required
     * @param _duration The duration of the loan in days
     */
    function issueLoan(
        address _borrower,
        uint256 _amount,
        uint256 _interestRate,
        uint256 _collateral,
        uint256 _duration
    )
        external
        onlyRole(RISK_MANAGER_ROLE)
        onlyValidUser(_borrower)
        withinLoanLimits(_amount)
        nonReentrant
        whenNotPaused
    {
        require(_duration <= MAX_LOAN_DURATION, "Loan duration too long");
        require(
            userCollateralBalance[_borrower] >= _collateral,
            "Insufficient collateral balance"
        );

        UserProfile storage profile = users[_borrower];
        require(
            keccak256(abi.encode(calculateUserRiskLevel(_borrower))) !=
                keccak256(abi.encode("High")),
            "User risk level too high"
        );

        uint256 dueDate = block.timestamp + (_duration * 1 days);

        loanCounter++;
        loans[loanCounter] = Loan({
            loanId: loanCounter,
            borrower: _borrower,
            amount: _amount,
            collateral: _collateral,
            interestRate: _interestRate,
            dueDate: dueDate,
            repaymentDate: 0,
            latePaymentFee: 0,
            status: LoanStatus.ACTIVE,
            lastUpdateTimestamp: block.timestamp
        });

        userLoans[_borrower].push(loanCounter);
        profile.totalBorrowed += _amount;
        profile.lastLoanTimestamp = block.timestamp;
        profile.totalCollateralLocked += _collateral;
        userCollateralBalance[_borrower] -= _collateral;
        totalActiveLoanValue += _amount;

        emit LoanIssued(
            loanCounter,
            _borrower,
            _amount,
            _interestRate,
            _collateral,
            dueDate
        );
    }

    /**
     * @notice Calculate late payment fee
     * @param _loanId The ID of the loan
     * @return fee The calculated late payment fee
     */
    function calculateLatePaymentFee(
        uint256 _loanId
    ) public view onlyValidLoan(_loanId) returns (uint256 fee) {
        Loan memory loan = loans[_loanId];
        if (block.timestamp <= loan.dueDate + (GRACE_PERIOD_DAYS * 1 days)) {
            return 0;
        }

        uint256 daysLate = (block.timestamp - loan.dueDate) / 1 days;
        fee = (loan.amount * DAILY_LATE_FEE_PERCENTAGE * daysLate) / 100;
        return fee;
    }

    /**
     * @notice Repay a loan
     * @param _loanId The ID of the loan being repaid
     */
    function repayLoan(
        uint256 _loanId
    ) external nonReentrant whenNotPaused onlyValidLoan(_loanId) {
        Loan storage loan = loans[_loanId];
        require(
            msg.sender == loan.borrower,
            "Only borrower can repay the loan"
        );
        require(loan.status == LoanStatus.ACTIVE, "Loan is not active");

        uint256 latePaymentFee = calculateLatePaymentFee(_loanId);
        UserProfile storage profile = users[loan.borrower];

        loan.repaymentDate = block.timestamp;
        loan.latePaymentFee = latePaymentFee;
        loan.status = LoanStatus.REPAID;

        // Update trust score based on payment timing
        if (latePaymentFee == 0) {
            profile.onTimePaymentCount++;
            _updateTrustScore(loan.borrower, 10, "On-time payment");
        } else {
            profile.latePaymentCount++;
            uint256 daysLate = (block.timestamp - loan.dueDate) / 1 days;
            _updateTrustScore(
                loan.borrower,
                -(int256(daysLate) * 2),
                "Late payment penalty"
            );
        }

        profile.totalRepaid += loan.amount;
        profile.totalCollateralLocked -= loan.collateral;
        userCollateralBalance[loan.borrower] += loan.collateral;
        totalActiveLoanValue -= loan.amount;

        emit LoanRepaid(
            _loanId,
            loan.borrower,
            loan.amount,
            latePaymentFee,
            profile.trustScore
        );
    }

    /**
     * @notice Record a loan default
     * @param _loanId The ID of the loan in default
     */
    function recordDefault(
        uint256 _loanId
    ) external onlyRole(RISK_MANAGER_ROLE) onlyValidLoan(_loanId) {
        Loan storage loan = loans[_loanId];
        require(loan.status == LoanStatus.ACTIVE, "Loan is not active");
        require(
            block.timestamp > loan.dueDate + (GRACE_PERIOD_DAYS * 1 days),
            "Grace period not expired"
        );

        UserProfile storage profile = users[loan.borrower];
        profile.defaultCount++;
        loan.status = LoanStatus.DEFAULTED;

        // Severe trust score penalty for default
        _updateTrustScore(loan.borrower, -50, "Loan default penalty");

        if (profile.defaultCount >= 3) {
            profile.isBlacklisted = true;
            emit UserBlacklisted(loan.borrower, "Multiple defaults");
        }

        emit DefaultRecorded(
            loan.borrower,
            _loanId,
            profile.defaultCount,
            profile.trustScore
        );
    }

    /**
     * @notice Update user's trust score
     * @param _user The user's address
     * @param _change The change in trust score (positive or negative)
     * @param _reason The reason for the update
     */
    function _updateTrustScore(
        address _user,
        int256 _change,
        string memory _reason
    ) internal {
        UserProfile storage profile = users[_user];
        uint256 oldScore = profile.trustScore;

        if (_change > 0) {
            profile.trustScore = min(
                profile.trustScore + uint256(_change),
                MAX_TRUST_SCORE
            );
        } else {
            uint256 decrease = uint256(-_change);
            if (decrease >= profile.trustScore) {
                profile.trustScore = MIN_TRUST_SCORE;
            } else {
                profile.trustScore -= decrease;
            }
        }

        emit TrustScoreUpdated(_user, oldScore, profile.trustScore, _reason);
    }

    /**
     * @notice Calculate risk level based on trust score and loan history
     * @param _user The address of the user
     * @return string The calculated risk level
     */
    function calculateUserRiskLevel(
        address _user
    ) public view onlyValidUser(_user) returns (string memory) {
        UserProfile memory profile = users[_user];

        if (profile.defaultCount > 0) {
            return "High";
        }

        if (profile.trustScore >= 800) {
            return "Very Low";
        } else if (profile.trustScore >= 600) {
            return "Low";
        } else if (profile.trustScore >= 400) {
            return "Medium";
        } else if (profile.trustScore >= 200) {
            return "Medium High";
        } else {
            return "High";
        }
    }

    /**
     * @notice Deposit collateral
     * @param _amount The amount of collateral to deposit
     */
    function depositCollateral(
        uint256 _amount
    ) external payable nonReentrant whenNotPaused {
        require(_amount > 0, "Amount must be greater than 0");
        require(msg.value == _amount, "Incorrect ETH amount sent");

        userCollateralBalance[msg.sender] += _amount;

        emit CollateralDeposited(
            msg.sender,
            _amount,
            userCollateralBalance[msg.sender]
        );
    }

    /**
     * @notice Withdraw available collateral
     * @param _amount The amount of collateral to withdraw
     */
    function withdrawCollateral(
        uint256 _amount
    ) external nonReentrant whenNotPaused {
        require(_amount > 0, "Amount must be greater than 0");
        require(
            userCollateralBalance[msg.sender] >= _amount,
            "Insufficient collateral balance"
        );

        userCollateralBalance[msg.sender] -= _amount;
        payable(msg.sender).transfer(_amount);

        emit CollateralWithdrawn(
            msg.sender,
            _amount,
            userCollateralBalance[msg.sender]
        );
    }

    // Utility functions
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /**
     * @notice Get detailed loan statistics for a user
     * @param _user The address of the user
     * @return activeLoans
     * @return completedLoans
     * @return totalAmount
     * @return avgRepaymentTime
     */
    function getUserLoanStats(
        address _user
    )
        external
        view
        returns (
            uint256 activeLoans,
            uint256 completedLoans,
            uint256 totalAmount,
            uint256 avgRepaymentTime
        )
    {
        uint256[] memory userLoanIds = userLoans[_user];
        uint256 totalRepaymentTime = 0;
        uint256 repaidLoans = 0;

        for (uint256 i = 0; i < userLoanIds.length; i++) {
            Loan memory loan = loans[userLoanIds[i]];
            if (loan.status == LoanStatus.ACTIVE) {
                activeLoans++;
                totalAmount += loan.amount;
            } else if (loan.status == LoanStatus.REPAID) {
                completedLoans++;
                totalAmount += loan.amount;
                totalRepaymentTime += (loan.repaymentDate -
                    loan.lastUpdateTimestamp);
                repaidLoans++;
            }
        }

        avgRepaymentTime = repaidLoans > 0
            ? totalRepaymentTime / repaidLoans
            : 0;
    }

    /**
     * @notice Liquidate defaulted loan
     * @param _loanId The ID of the loan to liquidate
     */
    function liquidateLoan(
        uint256 _loanId
    ) external onlyRole(RISK_MANAGER_ROLE) onlyValidLoan(_loanId) nonReentrant {
        Loan storage loan = loans[_loanId];
        require(
            loan.status == LoanStatus.DEFAULTED,
            "Loan must be in defaulted status"
        );

        UserProfile storage profile = users[loan.borrower];

        // Transfer collateral to contract
        profile.totalCollateralLocked -= loan.collateral;
        totalActiveLoanValue -= loan.amount;
        loan.status = LoanStatus.LIQUIDATED;

        // Apply additional penalties
        _updateTrustScore(loan.borrower, -25, "Loan liquidation penalty");

        emit LoanLiquidated(_loanId, loan.borrower);
    }

    /**
     * @notice Update platform fee percentage
     * @param _newFeePercentage New fee percentage
     */
    function updatePlatformFee(
        uint256 _newFeePercentage
    ) external onlyRole(ADMIN_ROLE) {
        require(_newFeePercentage <= 5, "Fee too high"); // Max 5%
        platformFeePercentage = _newFeePercentage;
    }

    /**
     * @notice Emergency pause contract
     */
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause contract
     */
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    // Function to receive ETH
    receive() external payable {}

    // Fallback function
    fallback() external payable {}
}
