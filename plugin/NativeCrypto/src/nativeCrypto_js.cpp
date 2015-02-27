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
#include <ctime>
#include "../public/tokenizer.h"
#include <json/reader.h>
#include <json/writer.h>
#include "nativeCrypto_js.hpp"
#include "nativeCrypto_ndk.hpp"
#include "util/util.hpp"

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
    if (strCommand == "ping") {
        return m_pNativeCryptoController->ping();
    }

    if (strCommand == "hashSha1") {
        result = m_pNativeCryptoController->getSha1(arg);
        result = m_pNativeCryptoController->toBase64(result);
    }
    if (strCommand == "hashSha512") {
        result = m_pNativeCryptoController->getSha512(arg);
        result = m_pNativeCryptoController->toBase64(result);
    }
    if (strCommand == "hashSha384") {
        result = m_pNativeCryptoController->getSha384(arg);
        result = m_pNativeCryptoController->toBase64(result);
    }
    if (strCommand == "hashSha256") {
        result = m_pNativeCryptoController->getSha256(arg);
        result = m_pNativeCryptoController->toBase64(result);
    }
    if (strCommand == "hashSha224") {
        result = m_pNativeCryptoController->getSha224(arg);
        result = m_pNativeCryptoController->toBase64(result);
    }
    if (strCommand == "hashMd5") {
        result = m_pNativeCryptoController->getMd5(arg);
        result = m_pNativeCryptoController->toBase64(result);
    }
    if (strCommand == "produceKey") {
        // result= m_pNativeCryptoController->produceKey(arg);
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

    /*
     if (strCommand == "testString") {
     return m_pNativeCryptoController->templateTestString();
     } else if (strCommand == "testStringInput") {
     return m_pNativeCryptoController->templateTestString(arg);
     } else if (strCommand == "templateProperty") {
     // if arg exists we are setting property
     if (arg != strCommand) {
     m_pNativeCryptoController->setTemplateProperty(arg);
     } else {
     return m_pNativeCryptoController->getTemplateProperty();
     }
     } else if (strCommand == "testAsync") {
     m_pNativeCryptoController->templateTestAsync(callbackId, arg);
     } else if (strCommand == "templateStartThread") {
     return m_pNativeCryptoController->templateStartThread(callbackId);
     } else if (strCommand == "templateStopThread") {
     return m_pNativeCryptoController->templateStopThread();
     }
     */
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
