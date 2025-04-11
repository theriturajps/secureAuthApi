// Email validation using regex
const isValidEmail = (email) => {
	const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
	return emailRegex.test(email);
};

// Check if string is empty
const isEmpty = (value) => {
	return value === undefined || value === null || value.trim() === '';
};

// Check minimum length
const isMinLength = (value, minLength) => {
	return value && value.length >= minLength;
};

// Check maximum length
const isMaxLength = (value, maxLength) => {
	return value && value.length <= maxLength;
};

// Validate username (alphanumeric + underscore)
const isValidUsername = (username) => {
	const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
	return usernameRegex.test(username);
};

// Check if strings match (for password confirmation)
const doStringsMatch = (str1, str2) => {
	return str1 === str2;
};

module.exports = {
	isValidEmail,
	isEmpty,
	isMinLength,
	isMaxLength,
	isValidUsername,
	doStringsMatch
};