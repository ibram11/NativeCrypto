/*
 *
 * Copyright (c) 2013 BlackBerry Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string>
#include <sstream>
#include <json/reader.h>
#include <json/writer.h>
#include <pthread.h>
#include <huctx.h>
#include <hugse56.h>
#include <humd5.h>
#include <husha1.h>
#include <husha2.h>
#include <hurandom.h>
#include <huseed.h>
#include <huaes.h>
#include <hursa.h>
#include <sbreturn.h>
#include <QByteArray>
#include <QString>
#include "nativeCrypto_ndk.hpp"
#include "nativeCrypto_js.hpp"
#include "util/util.hpp"
#include <hurandom.h>
#include <openssl/ripemd.h>

namespace webworks
{

    NativeCryptoNDK::NativeCryptoNDK(NativeCryptoJS *parent) :
            m_pParent(parent)
    {
        sbCtx = NULL;
        rngCtx = NULL;
        try {
            int error = hu_GlobalCtxCreateDefault(&sbCtx);
            error = hu_RegisterSbg56(sbCtx);
            error = hu_InitSbg56(sbCtx);
            error = hu_RegisterSystemSeed(sbCtx);
            error = hu_RngDrbgCreate(HU_DRBG_CIPHER, 256, 0, 0, NULL, NULL, &rngCtx, sbCtx);
        } catch (std::string & message) {
            std::stringstream out;
            out << message;
        }

    }

    NativeCryptoNDK::~NativeCryptoNDK()
    {
        if (sbCtx != NULL) {
            hu_GlobalCtxDestroy(&sbCtx);
            sbCtx = NULL;
        }
    }

    sb_GlobalCtx NativeCryptoNDK::context()
    {
        return sbCtx;
    }
    sb_RNGCtx NativeCryptoNDK::randomContext()
    {
        return rngCtx;
    }

    std::string NativeCryptoNDK::ping()
    {
        m_pParent->getLog()->debug("ping-pong");
        return "pong";
    }

    unsigned char * NativeCryptoNDK::random(size_t size)
    {
        unsigned char * data = new unsigned char[size];
//        for (unsigned int i = 0; i < size; i++) {
//            data[i] = '\0';
//        }
        int rc = hu_RngGetBytes(rngCtx, size, data, sbCtx);
        if (rc != SB_SUCCESS) {
            throw std::string("Could not get random bytes", rc);
        }
        return data;
    }

    std::string NativeCryptoNDK::toBase64(std::string digest)
    {
        QByteArray text = QByteArray(reinterpret_cast<const char *>(digest.data()),
                digest.length());
        return text.toBase64().data();
    }

    std::string NativeCryptoNDK::fromBase64(std::string text)
    {
//        QByteArray toHashTmp(text.c_str(), text.length());
//        QByteArray toHash = QByteArray::fromBase64(toHashTmp);
//        std::string toHashStr(toHash.constData(), toHash.length());
//        toHashTmp = NULL;
//        toHash = NULL;
//        return toHashStr;
        size_t dataLen;
        unsigned char* data;
        this->fromB64(text, data, dataLen);
        std::string result(reinterpret_cast<const char *>(data), dataLen);
        return result;
    }



    void NativeCryptoNDK::fromB64(std::string encoded, unsigned char * & data, size_t & dataLen) {
        std::string encoded2;
        for (size_t i = 0; i < encoded.length(); ++i) {
            char c = encoded[i];
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
                encoded2 += c;
            } else {
                    throw std::string("Base64 data invalid");
            }
        }

        if (encoded2.length() == 0) {
            data = NULL;
            dataLen = 0;
            return;
        }

        if (encoded2.length() % 4 != 0) {
            throw std::string("Base64 encoded length should by multiple of 4");
        }

        dataLen = (encoded2.length() / 4) * 3;

        if (encoded2[encoded2.length() - 1] == '=') {
            dataLen--;
            if (encoded2[encoded2.length() - 2] == '=') {
                dataLen--;
            }
        }

        data = new unsigned char[dataLen];

        int offset = 0;
        size_t outOffset = 0;

        for (size_t i = 0; i < dataLen; i += 3) {
            unsigned char v[3];
            unsigned char e[4];
            for (int j = 0; j < 4; ++j) {
                e[j] = b64Nibble(encoded2[offset++]);
            }
            v[0] = e[0] << 2 | ((e[1] >> 4) & 0x3);
            v[1] = e[1] << 4 | ((e[2] >> 2) & 0xf);
            v[2] = e[2] << 6 | ((e[3] & 0x3f));
            for (int j = 0; j < 3 && outOffset < dataLen; ++j) {
                data[outOffset++] = v[j];
            }
        }
    }

    std::string NativeCryptoNDK::getMd5(std::string toHash)
    {
        size_t inputLength = toHash.length();
        //m_pParent->getLog()->debug(reinterpret_cast<const char*> (toHash.constData() ) );

        size_t digestLen = SB_MD5_DIGEST_LEN;
        unsigned char digest[digestLen];
//        for (size_t i = 0; i < digestLen; ++i) {
//            digest[i] = i;
//        }
        if (SB_SUCCESS
                != hu_MD5Msg(digestLen, NULL, inputLength,
                        reinterpret_cast<const unsigned char *>(toHash.data()), digest,
                        context())) {
            throw std::string("Could not call hash function");
        }
        std::string result(reinterpret_cast<char *>(digest), digestLen);
        return result;
    }

    std::string NativeCryptoNDK::getSha1(std::string toHash)
    {
//        stringstream ss;
//        ss<< toHash.length();
//        std::string sss=ss.str();
//        m_pParent->getLog()->debug(("getSha1 "+sss+" "+toHash).data());
        size_t inputLength = toHash.length();
        size_t digestLen = SB_SHA1_DIGEST_LEN;
        unsigned char digest[digestLen];
//        for (size_t i = 0; i < digestLen; ++i) {
//            digest[i] = i;
//        }
        if (SB_SUCCESS
                != hu_SHA1Msg(digestLen, NULL, inputLength,
                        reinterpret_cast<const unsigned char *>(toHash.data()), digest,
                        context())) {
            throw std::string("Could not call hash function");
        }
        std::string result(reinterpret_cast<char *>(digest), digestLen);
//        m_pParent->getLog()->debug(("getSha1 calculated "+result).data());
        return result;

    }
    std::string NativeCryptoNDK::getSha224(std::string toHash)
    {
        size_t inputLength = toHash.length();
        //m_pParent->getLog()->debug(reinterpret_cast<const char*> (toHash.constData() ) );

        size_t digestLen = SB_SHA224_DIGEST_LEN;
        unsigned char digest[digestLen];
//        for (size_t i = 0; i < digestLen; ++i) {
//            digest[i] = i;
//        }
        if (SB_SUCCESS
                != hu_SHA224Msg(digestLen, NULL, inputLength,
                        reinterpret_cast<const unsigned char *>(toHash.data()), digest,
                        context())) {
            throw std::string("Could not call hash function");
        }
        std::string result(reinterpret_cast<char *>(digest), digestLen);
        return result;
    }
    std::string NativeCryptoNDK::getSha256(std::string toHash)
    {
        size_t inputLength = toHash.length();
        size_t digestLen = SB_SHA256_DIGEST_LEN;
        unsigned char digest[digestLen];
//        for (size_t i = 0; i < digestLen; ++i) {
//            digest[i] = i;
//        }
        if (SB_SUCCESS
                != hu_SHA256Msg(digestLen, NULL, inputLength,
                        reinterpret_cast<const unsigned char *>(toHash.data()), digest,
                        context())) {
            throw std::string("Could not call hash function");
        }
        std::string result(reinterpret_cast<char *>(digest), digestLen);
        return result;

    }
    std::string NativeCryptoNDK::getSha384(std::string toHash)
    {
        size_t inputLength = toHash.length();
        //m_pParent->getLog()->debug(reinterpret_cast<const char*> (toHash.constData() ) );

        size_t digestLen = SB_SHA384_DIGEST_LEN;
        unsigned char digest[digestLen];
//        for (size_t i = 0; i < digestLen; ++i) {
//            digest[i] = i;
//        }
        if (SB_SUCCESS
                != hu_SHA384Msg(digestLen, NULL, inputLength,
                        reinterpret_cast<const unsigned char *>(toHash.data()), digest,
                        context())) {
            throw std::string("Could not call hash function");
        }
        std::string result(reinterpret_cast<char *>(digest), digestLen);
        return result;
    }

    std::string NativeCryptoNDK::getSha512(std::string toHash)
    {
        size_t inputLength = toHash.length();

//                stringstream ss;
//                ss<< toHash.length();
//                std::string sss=ss.str();
//                m_pParent->getLog()->debug(("getSha512 "+sss+" "+toHash).data());

//m_pParent->getLog()->debug(reinterpret_cast<const char*> (toHash.constData() ) );

        size_t digestLen = SB_SHA512_DIGEST_LEN;
        unsigned char digest[digestLen];
//        for (size_t i = 0; i < digestLen; ++i) {
//            digest[i] = i;
//        }
        if (SB_SUCCESS
                != hu_SHA512Msg(digestLen, NULL, inputLength,
                        reinterpret_cast<const unsigned char *>(toHash.data()), digest,
                        context())) {
            throw std::string("Could not call hash function");
        }
        std::string result(reinterpret_cast<char *>(digest), digestLen);
        return result;
    }

    std::string NativeCryptoNDK::getAes128ecb(std::string keyStr, std::string blockStr)
    {
        int mode = SB_AES_ECB;
        unsigned char resultBytes[blockStr.length()];

        stringstream ss;
        ss << blockStr.length();
        std::string sss = ss.str();
//        m_pParent->getLog()->debug(("getAes128ecb " + sss + " " + keyStr+ " "+ blockStr).data());

        if ((blockStr.length() % 16) != 0) {
            m_pParent->getLog()->error("Input not multiple of 128 bits. Use padding.");
            throw std::string("Input not multiple of 128 bits. Use padding.");
        }

        sb_Params params;
        hu_AESParamsCreate(SB_AES_ECB, SB_AES_128_BLOCK_BITS, NULL, NULL, &params, this->context());
//        m_pParent->getLog()->debug("Params created");
//        AESParams params(*this, mode, SB_AES_128_BLOCK_BITS, false);

        sb_Key key;
        hu_AESKeySet(params, keyStr.length() * 8, reinterpret_cast<const unsigned char *>(keyStr.data()), &key, this->context());
//        AESKey key(params, keyStr);
//        m_pParent->getLog()->debug("Key created");

        sb_Context context;
        hu_AESBeginV2(params, key, mode, 0, NULL, &context, this->context());
//        AESContext context(params, key, mode);
//        m_pParent->getLog()->debug("Context created");
//        context.crypt(blockStr, resultBytes, true);

        hu_AESEncrypt(context, blockStr.length(), reinterpret_cast<const unsigned char *>(blockStr.data()), resultBytes, this->context());

        std::string result(reinterpret_cast<char *>(resultBytes), blockStr.length());
//        m_pParent->getLog()->debug(("getAes128ecb result: "+ result).data());
        return result;
    }

    std::string NativeCryptoNDK::getRipemd160(std::string toHash)
    {
        size_t digestLen = RIPEMD160_DIGEST_LENGTH;
        unsigned char digest[digestLen];
        RIPEMD160(reinterpret_cast<const unsigned char *>(toHash.data()), toHash.length(), digest);
        std::string result(reinterpret_cast<char *>(digest), digestLen);
        return result;
    }

    std::string NativeCryptoNDK::encodeRsa(size_t nLen,
                            std::string e, std::string n,
                            std::string input){
        sb_Params params;
        stringstream ss;
        m_pParent->getLog()->debug("start");
        int stepResult=hu_RSAParamsCreate(nLen, this->randomContext(), NULL, &params,  this->context());
        m_pParent->getLog()->debug("params created");
        sb_PublicKey publicKey;
        sb_PrivateKey privateKey;

        std::string nm;
        ss<<n.length();
        ss<<" ";
        ss<<input.length();
        m_pParent->getLog()->debug(ss.str().data());
        ss.clear();

        stepResult=hu_RSAKeySet(params,
//                         e.length(), reinterpret_cast<const unsigned char *>(e.data()),
                         0, NULL,
                         n.length(), reinterpret_cast<const unsigned char *>(n.data()),
                         0, NULL,
                         0, NULL,
        //                 pLen, reinterpret_cast<const unsigned char *>(p.data()),
                         0, NULL,
        //                 qLen, reinterpret_cast<const unsigned char *>(q.data()),
                        0, NULL,
        //                size_t dModPLen, const unsigned char *dModPm1,
                        0, NULL,
        //                size_t dModQLen, const unsigned char *dModQm1,
                        0, NULL,
        //                size_t qInvLen, const unsigned char *qInvModP,
                        NULL, &publicKey,
                        this->context());

        std::string sss;

        if (stepResult!=SB_SUCCESS){
            ss << stepResult;
            sss = ss.str();
            m_pParent->getLog()->error(("returning error!"+sss).data());
            return "ERROR "+sss;
        }else{
            m_pParent->getLog()->debug("keys created");
        }

        size_t outputSize=nLen/8;
        size_t inputSize=input.length();
        unsigned char output[outputSize];
        stepResult=hu_RSAPublicEncrypt(params, publicKey, reinterpret_cast<const unsigned char *>(input.data()), output, this->context());
        if (stepResult!=SB_SUCCESS){
            ss << stepResult;
            sss = ss.str();
            m_pParent->getLog()->error(("returning error!"));
            return "ERROR "+sss;
        }else{
            m_pParent->getLog()->debug(("encrypted "+sss).data());
        }

        QByteArray result = QByteArray(reinterpret_cast<char *>(output), outputSize);
        m_pParent->getLog()->debug(result.toBase64().data());
        return result.toBase64().data();
    }


    std::string NativeCryptoNDK::decodeRsa(size_t eLen, size_t nLen, size_t dLen, size_t pLen, size_t qLen,
            std::string e, std::string n, std::string d, std::string p, std::string q,
            std::string input){
        sb_Params params;
        int stepResult=hu_RSAParamsCreate(nLen, NULL, NULL, &params,  this->context());
        stringstream ss;

        sb_PublicKey publicKey;
        sb_PrivateKey privateKey;

        stepResult=hu_RSAKeySet(params,
                 e.length(), reinterpret_cast<const unsigned char *>(e.data()),
                 n.length(), reinterpret_cast<const unsigned char *>(n.data()),
                 d.length(), reinterpret_cast<const unsigned char *>(d.data()),
//                 0, NULL,
                 pLen, reinterpret_cast<const unsigned char *>(p.data()),
//                 0, NULL,
                 qLen, reinterpret_cast<const unsigned char *>(q.data()),
                0, NULL,
//                size_t dModPLen, const unsigned char *dModPm1,
                0, NULL,
//                size_t dModQLen, const unsigned char *dModQm1,
                0, NULL,
//                size_t qInvLen, const unsigned char *qInvModP,
                &privateKey, &publicKey,
                this->context());
//        ss << stepResult;
//        std::string sss = ss.str();
//        ss.clear();
//        m_pParent->getLog()->debug(("keys created "+sss).data());

        size_t outputSize=nLen/8;
        unsigned char output[outputSize];

//        stepResult=hu_RSAPublicDecrypt(params, publicKey, reinterpret_cast<const unsigned char *>(input.data()), output, this->context());
        stepResult=hu_RSAPKCS1v15Dec(params, privateKey, input.length(), reinterpret_cast<const unsigned char *>(input.data()), &outputSize, output, this->context());

        QByteArray result = QByteArray(reinterpret_cast<char *>(output), outputSize);
        m_pParent->getLog()->debug(result.toBase64().data());
        return result.toBase64().data();
    }

    std::string NativeCryptoNDK::produceKeyByPassword(std::string passphraseB64, size_t numBytes,
            int algorithm, std::string type, size_t c, std::string saltB64)
    {
        std::string passphrase = fromBase64(passphraseB64);
        std::string salt = fromBase64(saltB64);
        std::string result = "";
        std::string prefix = "";
//        stringstream ss;
//        ss << numBytes;
//        string str = ss.str();
//        m_pParent->getLog()->debug(("loop until len "+str).c_str());
        while (result.length() < numBytes) {
            result += (round(prefix, passphrase, algorithm, type, c, salt));
            prefix += ('\0');
//            m_pParent->getLog()->debug("produceKeyByPassword loop finished ");
        }
        if (result.length() > numBytes) {
            result = result.substr(0, numBytes);
        }
//        m_pParent->getLog()->debug("produceKeyByPassword finished");
        return result;
    }

    std::string NativeCryptoNDK::round(std::string prefix, std::string passphrase, int algorithm,
            std::string type, size_t c, std::string salt)
    {
//        m_pParent->getLog()->debug(("round "+type).c_str());
        if (type == "simple") {
            return hash(algorithm, prefix + passphrase);
        }
        if (type == "salted") {
            return hash(algorithm, prefix + salt + passphrase);
        }
        if (type == "iterated") {
            std::string isp;
            size_t count = getCount(c);
            std::string data = salt + passphrase;
            while (isp.length() < count) {
                isp += data;
            }
            if (isp.length() > count) {
                isp = isp.substr(0, count);
            }
            return hash(algorithm, prefix + isp);
        }
        return NULL;
    }

    std::string NativeCryptoNDK::hash(int algorithm, std::string content)
    {
        if (algorithm == 1) {
//            m_pParent->getLog()->debug("hash getMd5");
            return getMd5(content);
        } else if (algorithm == 2) {
//            m_pParent->getLog()->debug("hash getSha1");
            return getSha1(content);
        } else if (algorithm == 3) {
//            m_pParent->getLog()->debug("hash getRipemd160");
            return getRipemd160(content);
        } else if (algorithm == 8) {
//            m_pParent->getLog()->debug("hash getSha256");
            return getSha256(content);
        } else if (algorithm == 9) {
//            m_pParent->getLog()->debug("hash getSha384");
            return getSha384(content);
        } else if (algorithm == 10) {
//            m_pParent->getLog()->debug("hash getSha512");
            return getSha512(content);
        } else if (algorithm == 11) {
//            m_pParent->getLog()->debug("hash getSha224");
            return getSha224(content);
        }
        return NULL;
    }

    long NativeCryptoNDK::getCount(size_t c)
    {
        size_t expbias = 6;
        return (16 + (c & 15)) << ((c >> 4) + expbias);
    }

    unsigned char NativeCryptoNDK::b64Nibble(unsigned char c) {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        } else if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        } else if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        } else if (c == '+') {
            return 62;
        } else if (c == '/') {
            return 63;
        }
        return 0;
    }


} /* namespace webworks */
