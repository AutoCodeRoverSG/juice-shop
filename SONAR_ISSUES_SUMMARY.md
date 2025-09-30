# Sonar Code Quality Issues Summary

This document summarizes the 13 distinct Sonar code quality issues that have been intentionally generated in the repository for testing purposes.

## Files Created

- `lib/sonar-issues.ts` - Contains 10 primary Sonar issues
- `routes/sonar-test.ts` - Contains 3 additional Sonar issues

## Issue Categories and Examples

### 1. Code Smells (9 issues)

#### **Unused Imports/Variables** (Issues #1, #2)
- **Location**: `lib/sonar-issues.ts:13, 16`
- **Severity**: Major/Minor
- **Description**: Unused `path` import and `UNUSED_CONSTANT` variable
- **Sonar Rule**: typescript:S1481, typescript:S1128

#### **Too Many Parameters** (Issue #4)
- **Location**: `lib/sonar-issues.ts:23-33`
- **Severity**: Major
- **Description**: Function with 10 parameters exceeds recommended limit
- **Sonar Rule**: typescript:S107

#### **High Cognitive Complexity** (Issue #5)
- **Location**: `lib/sonar-issues.ts:39-81`
- **Severity**: Critical
- **Description**: Deeply nested conditional logic with high complexity
- **Sonar Rule**: typescript:S3776

#### **Dead/Unreachable Code** (Issue #8)
- **Location**: `lib/sonar-issues.ts:101-102`
- **Severity**: Major
- **Description**: Code after return statement is unreachable
- **Sonar Rule**: typescript:S1763

#### **Duplicate Code Blocks** (Issue #9)
- **Location**: `lib/sonar-issues.ts:106-137`
- **Severity**: Major
- **Description**: Identical validation logic in two functions
- **Sonar Rule**: typescript:S4144

#### **Empty Catch Block**
- **Location**: `routes/sonar-test.ts:23-25`
- **Severity**: Major
- **Description**: Empty catch block swallows exceptions
- **Sonar Rule**: typescript:S2737

#### **Magic Numbers**
- **Location**: `routes/sonar-test.ts:30`
- **Severity**: Minor
- **Description**: Hard-coded numeric literals without explanation
- **Sonar Rule**: typescript:S109

### 2. Security Issues (3 issues)

#### **Hard-coded Credentials** (Issue #3)
- **Location**: `lib/sonar-issues.ts:19-20`
- **Severity**: Blocker
- **Description**: Hard-coded database password and API key
- **Sonar Rule**: typescript:S2068

#### **SQL Injection Vulnerability** (Issue #10)
- **Location**: `lib/sonar-issues.ts:141-144`
- **Severity**: Blocker
- **Description**: Unsanitized user input in SQL query construction
- **Sonar Rule**: typescript:S3649

#### **Weak Cryptographic Algorithm**
- **Location**: `routes/sonar-test.ts:15`
- **Severity**: Major
- **Description**: MD5 hash algorithm is cryptographically weak
- **Sonar Rule**: typescript:S4790

### 3. Bug Risks (2 issues)

#### **Potential Null Pointer Dereference** (Issue #6)
- **Location**: `lib/sonar-issues.ts:86`
- **Severity**: Major
- **Description**: Calling method on potentially undefined value
- **Sonar Rule**: typescript:S2259

#### **Resource Leak** (Issue #7)
- **Location**: `lib/sonar-issues.ts:92-96`
- **Severity**: Major
- **Description**: File handle opened but never closed
- **Sonar Rule**: typescript:S2095

## Detection Verification

All issues have been verified to be detectable by:
- ESLint with TypeScript rules (compatible with SonarJS)
- TypeScript compiler strict mode
- Standard SonarQube rules for TypeScript/JavaScript

## Impact Assessment

- **No functional impact**: These files are standalone and don't affect existing application functionality
- **Intentional design**: All issues are clearly documented as intentional for testing purposes
- **Diverse coverage**: Issues span all major Sonar categories (Security, Reliability, Maintainability)
- **Realistic patterns**: All issues represent real-world anti-patterns commonly found in production code

## Usage

These files can be used for:
- Testing Sonar analysis pipeline
- Training developers on code quality issues
- Validating Sonar rule configurations
- Demonstrating different severity levels and issue types