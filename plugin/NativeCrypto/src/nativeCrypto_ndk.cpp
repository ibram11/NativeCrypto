/*
 * Copyright (c) 2013 BlackBerry Limited
 *
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
        QByteArray text = QByteArray(reinterpret_cast<const char *>(digest.data()), digest.length());
        return text.toBase64().data();
    }

    std::string NativeCryptoNDK::fromBase64(std::string text)
        {
               QByteArray toHashTmp(text.c_str(), text.length());
               QByteArray toHash = QByteArray::fromBase64(toHashTmp);
               std::string toHashStr(toHash.constData(), toHash.length());
               toHashTmp=NULL;
               toHash=NULL;
               return toHashStr;
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
                        reinterpret_cast<const unsigned char *>(toHash.data()), digest, context())) {
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
                        reinterpret_cast<const unsigned char *>(toHash.data()), digest, context())) {
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
                        reinterpret_cast<const unsigned char *>(toHash.data()), digest, context())) {
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
                        reinterpret_cast<const unsigned char *>(toHash.data()), digest, context())) {
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
                        reinterpret_cast<const unsigned char *>(toHash.data()), digest, context())) {
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
                        reinterpret_cast<const unsigned char *>(toHash.data()), digest, context())) {
            throw std::string("Could not call hash function");
        }
        std::string result(reinterpret_cast<char *>(digest), digestLen);
        return result;
    }

    std::string NativeCryptoNDK::getRipemd160(std::string toHash){
        size_t digestLen = RIPEMD160_DIGEST_LENGTH;
        unsigned char digest[digestLen];
        RIPEMD160(reinterpret_cast<const unsigned char *>(toHash.data()), toHash.length(), digest);
        std::string result(reinterpret_cast<char *>(digest), digestLen);
        return result;
    }

    std::string NativeCryptoNDK::produceKeyByPassword(std::string passphraseB64, size_t numBytes,
            int algorithm, std::string type, size_t c, std::string saltB64)
    {
        std::string passphrase=fromBase64(passphraseB64);
        std::string salt=fromBase64(saltB64);
        std::string result = "";
        std::string prefix = "";
//        stringstream ss;
//        ss << numBytes;
//        string str = ss.str();
//        m_pParent->getLog()->debug(("loop until len "+str).c_str());
        while (result.length() < numBytes) {
            result+=(round(prefix, passphrase, algorithm, type, c, salt));
            prefix+=('\0');
//            m_pParent->getLog()->debug("produceKeyByPassword loop finished ");
        }
        if (result.length()>numBytes){
            result=result.substr(0, numBytes);
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
            std::string data = salt+passphrase;
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
        return  (16 + (c & 15)) << ((c >> 4) + expbias);
    }

} /* namespace webworks */
