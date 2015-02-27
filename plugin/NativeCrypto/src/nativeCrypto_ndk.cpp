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
        for (unsigned int i = 0; i < size; i++) {
            data[i] = '\0';
        }
        int rc = hu_RngGetBytes(rngCtx, size, data, sbCtx);
        if (rc != SB_SUCCESS) {
            throw std::string("Could not get random bytes", rc);
        }
        return data;
    }

    std::string NativeCryptoNDK::toBase64(std::string digest)
    {
        QByteArray text = QByteArray(reinterpret_cast<const char *>(digest.c_str()),
                digest.length());
        return text.toBase64().data();
    }

    std::string NativeCryptoNDK::getMd5(std::string arg)
    {
        QByteArray toHashTmp(arg.c_str(), arg.length());
        QByteArray toHash = QByteArray::fromBase64(toHashTmp);
        size_t inputLength = toHash.length();
        //m_pParent->getLog()->debug(reinterpret_cast<const char*> (toHash.constData() ) );

        size_t digestLen = SB_MD5_DIGEST_LEN;
        unsigned char digest[digestLen];
        for (size_t i = 0; i < digestLen; ++i) {
            digest[i] = i;
        }
        if (SB_SUCCESS
                != hu_MD5Msg(digestLen, NULL, inputLength,
                        reinterpret_cast<unsigned char *>(toHash.data()), digest, context())) {
            throw std::string("Could not call hash function");
        }
        std::string result(reinterpret_cast<char *>(digest), digestLen);
        /*std::string result =getStringFromArray(digest,digestLen);
         char buffer[256];
         snprintf(buffer, sizeof(buffer), "(%i, %i, %s)", arg.length(), inputLength, result.c_str());
         m_pParent->getLog()->debug(buffer);*/
        return result;
    }

    std::string NativeCryptoNDK::getSha1(std::string arg)
    {
        QByteArray toHashTmp(arg.c_str(), arg.length());
        QByteArray toHash = QByteArray::fromBase64(toHashTmp);
        size_t inputLength = toHash.length();
        //m_pParent->getLog()->debug(reinterpret_cast<const char*> (toHash.constData() ) );

        size_t digestLen = SB_SHA1_DIGEST_LEN;
        unsigned char digest[digestLen];
        for (size_t i = 0; i < digestLen; ++i) {
            digest[i] = i;
        }
        if (SB_SUCCESS
                != hu_SHA1Msg(digestLen, NULL, inputLength,
                        reinterpret_cast<unsigned char *>(toHash.data()), digest, context())) {
            throw std::string("Could not call hash function");
        }
        std::string result(reinterpret_cast<char *>(digest), digestLen);
        /*std::string result =getStringFromArray(digest,digestLen);
         char buffer[256];
         snprintf(buffer, sizeof(buffer), "(%i, %i, %s)", arg.length(), inputLength, result.c_str());
         m_pParent->getLog()->debug(buffer);*/
        return result;

    }
    std::string NativeCryptoNDK::getSha224(std::string arg)
    {

        QByteArray toHashTmp(arg.c_str(), arg.length());
        QByteArray toHash = QByteArray::fromBase64(toHashTmp);
        size_t inputLength = toHash.length();
        //m_pParent->getLog()->debug(reinterpret_cast<const char*> (toHash.constData() ) );

        size_t digestLen = SB_SHA224_DIGEST_LEN;
        unsigned char digest[digestLen];
        for (size_t i = 0; i < digestLen; ++i) {
            digest[i] = i;
        }
        if (SB_SUCCESS
                != hu_SHA224Msg(digestLen, NULL, inputLength,
                        reinterpret_cast<unsigned char *>(toHash.data()), digest, context())) {
            throw std::string("Could not call hash function");
        }
        std::string result(reinterpret_cast<char *>(digest), digestLen);
        /*std::string result =getStringFromArray(digest,digestLen);
         char buffer[256];
         snprintf(buffer, sizeof(buffer), "(%i, %i, %s)", arg.length(), inputLength, result.c_str());
         m_pParent->getLog()->debug(buffer);*/
        return result;
    }
    std::string NativeCryptoNDK::getSha256(std::string arg)
    {

        QByteArray toHashTmp(arg.c_str(), arg.length());
        QByteArray toHash = QByteArray::fromBase64(toHashTmp);
        size_t inputLength = toHash.length();
        //m_pParent->getLog()->debug(reinterpret_cast<const char*> (toHash.constData() ) );

        size_t digestLen = SB_SHA256_DIGEST_LEN;
        unsigned char digest[digestLen];
        for (size_t i = 0; i < digestLen; ++i) {
            digest[i] = i;
        }
        if (SB_SUCCESS
                != hu_SHA256Msg(digestLen, NULL, inputLength,
                        reinterpret_cast<unsigned char *>(toHash.data()), digest, context())) {
            throw std::string("Could not call hash function");
        }
        std::string result(reinterpret_cast<char *>(digest), digestLen);
        /*std::string result =getStringFromArray(digest,digestLen);
         char buffer[256];
         snprintf(buffer, sizeof(buffer), "(%i, %i, %s)", arg.length(), inputLength, result.c_str());
         m_pParent->getLog()->debug(buffer);*/
        return result;

    }
    std::string NativeCryptoNDK::getSha384(std::string arg)
    {

        QByteArray toHashTmp(arg.c_str(), arg.length());
        QByteArray toHash = QByteArray::fromBase64(toHashTmp);
        size_t inputLength = toHash.length();
        //m_pParent->getLog()->debug(reinterpret_cast<const char*> (toHash.constData() ) );

        size_t digestLen = SB_SHA384_DIGEST_LEN;
        unsigned char digest[digestLen];
        for (size_t i = 0; i < digestLen; ++i) {
            digest[i] = i;
        }
        if (SB_SUCCESS
                != hu_SHA384Msg(digestLen, NULL, inputLength,
                        reinterpret_cast<unsigned char *>(toHash.data()), digest, context())) {
            throw std::string("Could not call hash function");
        }
        std::string result(reinterpret_cast<char *>(digest), digestLen);
        /*std::string result =getStringFromArray(digest,digestLen);
         char buffer[256];
         snprintf(buffer, sizeof(buffer), "(%i, %i, %s)", arg.length(), inputLength, result.c_str());
         m_pParent->getLog()->debug(buffer);*/
        return result;
    }
    std::string NativeCryptoNDK::getSha512(std::string arg)
    {
        QByteArray toHashTmp(arg.c_str(), arg.length());
        QByteArray toHash = QByteArray::fromBase64(toHashTmp);
        size_t inputLength = toHash.length();
        //m_pParent->getLog()->debug(reinterpret_cast<const char*> (toHash.constData() ) );

        size_t digestLen = SB_SHA512_DIGEST_LEN;
        unsigned char digest[digestLen];
        for (size_t i = 0; i < digestLen; ++i) {
            digest[i] = i;
        }
        if (SB_SUCCESS
                != hu_SHA512Msg(digestLen, NULL, inputLength,
                        reinterpret_cast<unsigned char *>(toHash.data()), digest, context())) {
            throw std::string("Could not call hash function");
        }
        std::string result(reinterpret_cast<char *>(digest), digestLen);
        /*std::string result =getStringFromArray(digest,digestLen);
         char buffer[256];
         snprintf(buffer, sizeof(buffer), "(%i, %i, %s)", arg.length(), inputLength, result.c_str());
         m_pParent->getLog()->debug(buffer);*/
        return result;
    }

    std::string NativeCryptoNDK::produceKey(std::string passphrase, size_t numBytes,
            size_t algorithm, std::string type, size_t c)
    {
        std::string result = "";
        std::string prefix = "";
        while (result.length() < numBytes) {
            result.append(round(prefix, passphrase, algorithm, type, c));
            prefix.append(char(0));
        }
        return result;
    }

    std::string NativeCryptoNDK::round(std::string prefix, std::string passphrase, size_t algorithm,
            std::string type, size_t c)
    {
        if (type == "simple") {
            return hash(algorithm, prefix + passphrase);
        }
        if (type == "salted") {
            std::string toHash = prefix;
            toHash.append(reinterpret_cast<const char *>(random(8)));
            toHash.append(passphrase);
            return hash(algorithm, toHash);
        }
        if (type == "iterated") {
            std::string isp;
            size_t count = getCount(c);
            std::string data = "";
            data.append(reinterpret_cast<const char *>(random(8)));
            data.append(passphrase);
            while (isp.length() * data.length() < count) {
                isp += data;
            }
            if (isp.length() > count) {
                isp = isp.substr(0, count);
            }
            return hash(algorithm, prefix + isp);
        }
        return NULL;
    }

    std::string NativeCryptoNDK::hash(size_t algorithm, std::string content)
    {
        if (algorithm == 1) {
            return getMd5(content);
        } else if (algorithm == 2) {
            return getSha1(content);
        } else if (algorithm == 3) {
            return NULL;
        } else if (algorithm == 8) {
            return getSha256(content);
        } else if (algorithm == 9) {
            return getSha384(content);
        } else if (algorithm == 10) {
            return getSha512(content);
        } else if (algorithm == 11) {
            return getSha224(content);
        }
        return NULL;
        /*
         * case 1:
         // - MD5 [HAC]
         return this.md5(data);
         case 2:
         // - SHA-1 [FIPS180]
         return this.sha1(data);
         case 3:
         // - RIPE-MD/160 [HAC]
         return this.ripemd(data);
         case 8:
         // - SHA256 [FIPS180]
         var sha256 = forge_sha256.create();
         sha256.update(data);
         return sha256.digest().getBytes();
         case 9:
         // - SHA384 [FIPS180]
         return this.sha384(data);
         case 10:
         // - SHA512 [FIPS180]
         return this.sha512(data);
         case 11:
         // - SHA224 [FIPS180]
         return this.sha224(data);
         */
    }

    size_t NativeCryptoNDK::getCount(size_t c)
    {
        size_t expbias = 6;
        return (16 + (c & 15)) << ((c >> 4) + expbias);
    }

} /* namespace webworks */
