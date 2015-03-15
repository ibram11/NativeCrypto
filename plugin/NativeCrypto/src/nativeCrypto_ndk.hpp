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

#ifndef NATIVECRYPTONDK_HPP_
#define NATIVECRYPTONDK_HPP_

#include <string>
#include <pthread.h>
#include <huctx.h>

class NativeCryptoJS;

namespace webworks
{

    class NativeCryptoNDK
    {
    public:
        explicit NativeCryptoNDK(NativeCryptoJS *parent = NULL);
        virtual ~NativeCryptoNDK();

        sb_GlobalCtx context();
        sb_RNGCtx randomContext();
        std::string ping();
        std::string toBase64(std::string content);
        std::string fromBase64(std::string content);

        unsigned char * random(size_t size);
        std::string getMd5(std::string arg);
        std::string getSha1(std::string arg);
        std::string getSha224(std::string arg);
        std::string getSha256(std::string arg);
        std::string getSha384(std::string arg);
        std::string getSha512(std::string arg);
        std::string getRipemd160(std::string arg);

        std::string getAes128ecb(std::string key, std::string block);

        std::string errorMessage(const char * message, int error);

        std::string produceKeyByPassword(std::string passphrase, size_t numBytes, int algorithm,
                std::string type, size_t c, std::string salt);

        std::string decodeRsa(size_t eLen, size_t nLen, size_t dLen, size_t pLen, size_t qLen,
                std::string e, std::string n, std::string d, std::string p, std::string q,
                std::string input);
        std::string encodeRsa(size_t nLen,
                        std::string e, std::string n,
                        std::string input);
        friend class AESParams;
        friend class AESKey;
        friend class AESContext;

    private:
        NativeCryptoJS *m_pParent;
        sb_GlobalCtx sbCtx;
        sb_RNGCtx rngCtx;

        void fromB64(std::string encoded, unsigned char * & data, size_t & dataLen);
        unsigned char b64Nibble(unsigned char c);

        std::string hash(int algorithm, std::string content);
        std::string round(std::string prefix, std::string passphrase, int algorithm,
                std::string type, size_t c, std::string salt);
        long getCount(size_t c);
    };
//
//    class AESParams {
//    public:
//        AESParams(NativeCryptoNDK & owner, int mode, size_t blockLen, bool withRandom);
//        virtual ~AESParams();
//
//    private:
//        NativeCryptoNDK & owner;
//        sb_Params params;
//
//        friend class AESKey;
//        friend class AESContext;
//    };
//    class AESKey {
//    public:
//        AESKey(AESParams & owner, size_t size);
//        AESKey(AESParams & owner, std::string & dt);
//        virtual ~AESKey();
//
//        void get(std::string & dt);
//    private:
//        AESParams & params;
//        sb_Key key;
//
//        friend class AESContext;
//    };
//    /**
//     * c++ wrapper for AES sb_Context
//     */
//    class AESContext {
//    public:
//        AESContext(AESParams &, AESKey &, int mode);
//        virtual ~AESContext();
//        void crypt(std::string & in, unsigned char * out, bool isEncrypt);
//    private:
//        AESParams & params;
//        sb_Context context;
//    };

} // namespace webworks

#endif /* NATIVECRYPTONDK_HPP_ */
