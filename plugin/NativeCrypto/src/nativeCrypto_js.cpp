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
#include <ctime>
#include "../public/tokenizer.h"
#include <json/reader.h>
#include <json/writer.h>
#include "nativeCrypto_js.hpp"
#include "nativeCrypto_ndk.hpp"
#include "util/util.hpp"
#include <QByteArray>
#include <QString>

using namespace std;

/**
 * Default constructor.
 */
NativeCryptoJS::NativeCryptoJS(const std::string& id) :
        m_id(id)
{
    m_pLogger = new webworks::Logger("NativeCryptoJS", this);
    m_pLogger->debug("m_pLogger created");
    m_pNativeCryptoController = new webworks::NativeCryptoNDK(this);
    m_pLogger->debug("m_pNativeCryptoController created");
}

/**
 * TemplateJS destructor.
 */
NativeCryptoJS::~NativeCryptoJS()
{
    if (m_pNativeCryptoController)
        delete m_pNativeCryptoController;
    if (m_pLogger)
        delete m_pLogger;
}

webworks::Logger* NativeCryptoJS::getLog()
{
    return m_pLogger;
}

/**
 * This method returns the list of objects implemented by this native
 * extension.
 */
char* onGetObjList()
{
    static char name[] = "NativeCryptoJS";
    return name;
}

/**
 * This method is used by JNext to instantiate the NativeCryptoJS object when
 * an object is created on the JavaScript server side.
 */
JSExt* onCreateObject(const string& className, const string& id)
{
    if (className == "NativeCryptoJS") {
        NativeCryptoJS* result = new NativeCryptoJS(id);
        result->getLog()->debug("NativeCryptoJS created");
        return result;
    }
    return NULL;
}

/**
 * Method used by JNext to determine if the object can be deleted.
 */
bool NativeCryptoJS::CanDelete()
{
    return true;
}

/**
 * It will be called from JNext JavaScript side with passed string.
 * This method implements the interface for the JavaScript to native binding
 * for invoking native code. This method is triggered when JNext.invoke is
 * called on the JavaScript side with this native objects id.
 */
string NativeCryptoJS::InvokeMethod(const string& command)
{
    clock_t begin = clock();
    // format must be: "command callbackId params"
    m_pLogger->debug(command.c_str());
    size_t commandIndex = command.find_first_of(" ");
    std::string strCommand = command.substr(0, commandIndex);
    size_t callbackIndex = command.find_first_of(" ", commandIndex + 1);
    std::string callbackId = command.substr(commandIndex + 1, callbackIndex - commandIndex - 1);
    std::string arg = command.substr(callbackIndex + 1, command.length());
    // based on the command given, run the appropriate method in template_ndk.cpp

    std::string result = "";

    m_pLogger->debug(strCommand.c_str());

    if (strCommand == "ping") {
        return m_pNativeCryptoController->ping();
    }
    if (strCommand == "ripemd160") {
        result = m_pNativeCryptoController->getRipemd160(m_pNativeCryptoController->fromBase64(arg));
        result = m_pNativeCryptoController->toBase64(result);
    }
    if (strCommand == "hashSha1") {
        result = m_pNativeCryptoController->getSha1(m_pNativeCryptoController->fromBase64(arg));
        result = m_pNativeCryptoController->toBase64(result);
    }
    if (strCommand == "hashSha512") {
        result = m_pNativeCryptoController->getSha512(m_pNativeCryptoController->fromBase64(arg));
        result = m_pNativeCryptoController->toBase64(result);
    }
    if (strCommand == "hashSha384") {
        result = m_pNativeCryptoController->getSha384(m_pNativeCryptoController->fromBase64(arg));
        result = m_pNativeCryptoController->toBase64(result);
    }
    if (strCommand == "hashSha256") {
        result = m_pNativeCryptoController->getSha256(m_pNativeCryptoController->fromBase64(arg));
        result = m_pNativeCryptoController->toBase64(result);
    }
    if (strCommand == "hashSha224") {
        result = m_pNativeCryptoController->getSha224(m_pNativeCryptoController->fromBase64(arg));
        result = m_pNativeCryptoController->toBase64(result);
    }
    if (strCommand == "hashMd5") {
        result = m_pNativeCryptoController->getMd5(m_pNativeCryptoController->fromBase64(arg));
        result = m_pNativeCryptoController->toBase64(result);
    }
    if (strCommand == "rsaEncrypt") {
        std::string nLen=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
        std::string eB64=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
        std::string nB64=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
        std::string mB64=arg.substr(0, arg.find_first_of(" "));
//        result = m_pNativeCryptoController->encodeRsa(
//                size_t(atoi(nLen.c_str())),
//                m_pNativeCryptoController->fromBase64(eB64), m_pNativeCryptoController->fromBase64(nB64),
//                m_pNativeCryptoController->fromBase64(mB64)
//                );
        result = m_pNativeCryptoController->encodeRsa(
                size_t(atoi(nLen.c_str())),
                eB64, nB64,
                m_pNativeCryptoController->fromBase64(mB64)
                );
        m_pLogger->debug(result.data());
        //result = m_pNativeCryptoController->toBase64(result);
    }
    if (strCommand == "rsaDecrypt") {
        std::string eLen=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
        std::string nLen=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
        std::string dLen=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
        std::string pLen=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
        std::string qLen=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);

        std::string eB64=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
        std::string nB64=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
        std::string dB64=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
        std::string pB64=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
        std::string qB64=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
        std::string mB64=arg.substr(0, arg.find_first_of(" "));
        result = m_pNativeCryptoController->decodeRsa(
                size_t(atoi(eLen.c_str())), size_t(atoi(nLen.c_str())), size_t(atoi(dLen.c_str())),
                size_t(atoi(pLen.c_str())), size_t(atoi(qLen.c_str())),
                m_pNativeCryptoController->fromBase64(eB64), m_pNativeCryptoController->fromBase64(nB64),
                m_pNativeCryptoController->fromBase64(dB64), m_pNativeCryptoController->fromBase64(pB64),
                m_pNativeCryptoController->fromBase64(qB64),
                m_pNativeCryptoController->fromBase64(mB64)
                );
        result = m_pNativeCryptoController->toBase64(result);

    }
    if (strCommand == "aes128ecb") {
        std::string keyB64=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
        std::string blockB64=arg.substr(0, arg.find_first_of(" "));
        result = m_pNativeCryptoController->getAes128ecb(m_pNativeCryptoController->fromBase64(keyB64), m_pNativeCryptoController->fromBase64(blockB64));
        result = m_pNativeCryptoController->toBase64(result);
    }

    if (strCommand == "produceKeyByPassword") {
//        m_pLogger->debug(arg.c_str());
        std::string passphrase=arg.substr(0, arg.find_first_of(" "));
//        m_pLogger->debug(passphrase.c_str());
        arg=arg.substr(arg.find_first_of(" ")+1);
        std::string numBytesStr=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
//        m_pLogger->debug(numBytesStr.c_str());
        std::string algorithmStr=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
//        m_pLogger->debug(algorithmStr.c_str());
        std::string typeStr=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
//        m_pLogger->debug(typeStr.c_str());
        std::string cStr=arg.substr(0, arg.find_first_of(" "));
        arg=arg.substr(arg.find_first_of(" ")+1);
//        m_pLogger->debug(cStr.c_str());
        std::string saltStr=arg;
//        m_pLogger->debug(saltStr.c_str());
        result = m_pNativeCryptoController->produceKeyByPassword(passphrase,
                size_t(atoi(numBytesStr.c_str())),
                int(atoi(algorithmStr.c_str())),
                typeStr,
                size_t(atoi(cStr.c_str())),
                saltStr);
        result = m_pNativeCryptoController->toBase64(result);
    }
    if (result.length() > 0) {
        clock_t end = clock();
        double time = (double(end - begin) / CLOCKS_PER_SEC);
        char buffer[256]; // make sure this is big enough!!!
        snprintf(buffer, sizeof(buffer), "(%f)", time);
        this->getLog()->debug(buffer);
        return result;
    }

    strCommand.append(";");
    strCommand.append(command);
    return strCommand;
}

// Notifies JavaScript of an event
void NativeCryptoJS::NotifyEvent(const std::string& event)
{
    std::string eventString = m_id + " ";
    eventString.append(event);
    SendPluginEvent(eventString.c_str(), m_pContext);
}
