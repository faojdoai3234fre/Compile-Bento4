#include "Ap4CommonEncryption.h"
#include "Bento4.hpp"

#include <QtCore/qbytearray.h>
#include <QtCore/qstring.h>

bool Bento4::decrypt(QByteArray& data, const QString& keyId, const QString& key) noexcept {

	if (key.size() != 32 || keyId.size() != 32) {
		return false;
	}

	// Create a key map object to hold decryption keys
	unsigned char keyID[16];
	unsigned char decryptionKey[16];
	AP4_ParseHex(keyId.toUtf8().constData(), keyID, 16);
	AP4_ParseHex(key.toUtf8().constData(), decryptionKey, 16);

	// Create a key map object to hold keys
	AP4_ProtectionKeyMap keyMap;
	keyMap.SetKeyForKid(keyID, decryptionKey, 16);

	// Create the input stream
	AP4_MemoryByteStream* inputBuffer = new AP4_MemoryByteStream(reinterpret_cast<const uint8_t*>(data.constData()), data.size());

	// Create the output stream
	AP4_MemoryByteStream* output = new AP4_MemoryByteStream();

	// Create the decrypting processor and set the decryption keys for it
	AP4_CencDecryptingProcessor* processor = new AP4_CencDecryptingProcessor(&keyMap);

	// Decrypt the file
	const AP4_Result result = processor->Process(*inputBuffer, *output);

	// Clean up variables that's not needed anymore
	delete processor;
	inputBuffer->Release();

	if (AP4_FAILED(result)) {
		output->Release();
		return false;
	}

	data = QByteArray(reinterpret_cast<const char*>(output->GetData()), output->GetDataSize());

	output->Release();

  return true;
}


bool Bento4::decrypt(QByteArray& data, const uint64_t trackId, const QString& key) noexcept {

	if (key.size() != 32) {
		return false;
	}

	// Create a key map object to hold decryption keys
	unsigned char decryptionKey[16];
	AP4_ParseHex(key.toUtf8().constData(), decryptionKey, 16);

	// Create a key map object to hold keys
	AP4_ProtectionKeyMap keyMap;
	keyMap.SetKey(trackId, decryptionKey, 16);

	// Create the input stream
	AP4_MemoryByteStream* inputBuffer = new AP4_MemoryByteStream(reinterpret_cast<const uint8_t*>(data.constData()), data.size());

	// Create the output stream
	AP4_MemoryByteStream* output = new AP4_MemoryByteStream();

	// Create the decrypting processor and set the decryption keys for it
	AP4_CencDecryptingProcessor* processor = new AP4_CencDecryptingProcessor(&keyMap);

	// Decrypt the file
	const AP4_Result result = processor->Process(*inputBuffer, *output);

	// Clean up variables that's not needed anymore
	delete processor;
	inputBuffer->Release();

	if (AP4_FAILED(result)) {
		output->Release();
		return false;
	}

	data = QByteArray(reinterpret_cast<const char*>(output->GetData()), output->GetDataSize());

	output->Release();

  return true;
}
