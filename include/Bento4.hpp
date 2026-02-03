#ifndef _BENTO4_H
#define _BENTO4_H

#include <QtCore/qbytearray.h>

// A class for working with ISO-MP4 files.
class Bento4 final {

private:
	Bento4() = delete;
	Bento4(const Bento4& other) = delete;
	Bento4& operator=(const Bento4& other) = delete;
	Bento4(Bento4&& other) = delete;
	Bento4& operator=(Bento4&& other) = delete;

public:
	/// <summary>Decrypt CENC-encrypted data. The decryption is hardware-accelerated using AES-NI.</summary>
	/// <param name="data">The encrypted data to decrypt. The decrypted data will be stored in this byte array. If the decryption fails, the original input data is untouched.</param>
	/// <param name="keyId">The key ID. The key ID must be hex-encoded and 16 bytes long (32 characters).</param>
	/// <param name="key">The decryption key. The key must be hex-encoded and 16 bytes long (32 characters).</param>
	/// <returns>True if the operation succeeded, false otherwise.</returns>
	static bool decrypt(QByteArray& data, const QString& keyId, const QString& key) noexcept;

	/// <summary>Decrypt CENC-encrypted data. The decryption is hardware-accelerated using AES-NI.</summary>
	/// <param name="data">The encrypted data to decrypt. The decrypted data will be stored in this byte array. If the decryption fails, the original input data is untouched.</param>
	/// <param name="trackId">The track ID.</param>
	/// <param name="key">The decryption key. The key must be hex-encoded and 16 bytes long (32 characters).</param>
	/// <returns>True if the operation succeeded, false otherwise.</returns>
	static bool decrypt(QByteArray& data, const uint64_t trackId, const QString& key) noexcept;

private:
	// Prevent the class from being instantiated on the heap.
	void* operator new(size_t);          // standard new
	void* operator new(size_t, void*);   // placement new
	void* operator new[](size_t);        // array new
	void* operator new[](size_t, void*); // placement array new
};

#endif // !_BENTO4_H
