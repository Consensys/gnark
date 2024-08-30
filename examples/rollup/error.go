/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rollup

import "errors"

var (
	// ErrSizeByteSlice memory checking
	ErrSizeByteSlice = errors.New("byte slice size is inconsistent with Account size")

	// ErrNonExistingAccount account not in the database
	ErrNonExistingAccount = errors.New("the account is not in the rollup database")

	// ErrWrongSignature wrong signature
	ErrWrongSignature = errors.New("invalid signature")

	// ErrAmountTooHigh the amount is bigger than the balance
	ErrAmountTooHigh = errors.New("amount is bigger than balance")

	// ErrNonce inconsistent nonce between transfer and account
	ErrNonce = errors.New("incorrect nonce")

	// ErrIndexConsistency the map publicKey(string) -> index(int) gives access to the account position.
	// Account has a field index, that should match position.
	ErrIndexConsistency = errors.New("account's position should match account's index")
)
