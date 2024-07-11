//
//  libipatcher.cpp
//  libipatcher
//
//  Created by tihmstar on 06.04.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#include <libipatcher/libipatcher.hpp>
#include <curl/curl.h>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string.h>

#include <libgeneral/macros.h>

#define WITH_IBOOT64PATCHER 1
#define WITH_IBOOT32PATCHER 1
#ifdef WITH_IBOOT64PATCHER

#include <libpatchfinder/machopatchfinder64.hpp>
#include <libpatchfinder/ibootpatchfinder/ibootpatchfinder64.hpp>
#include <libpatchfinder/kernelpatchfinder/kernelpatchfinder64.hpp>
#endif //WITH_IBOOT64PATCHER

#ifdef WITH_IBOOT32PATCHER
#include <libpatchfinder/machopatchfinder32.hpp>
#include <libpatchfinder/ibootpatchfinder/ibootpatchfinder32.hpp>
#include <libpatchfinder/kernelpatchfinder/kernelpatchfinder32.hpp>
#endif //WITH_IBOOT32PATCHER

#ifdef HAVE_IMG4TOOL
#include <img4tool/img4tool.hpp>
#endif //HAVE_IMG4TOOL

#ifdef HAVE_IMG3TOOL
#include <img3tool/img3tool.hpp>
#endif //HAVE_IMG3TOOL

#ifdef HAVE_LIBFRAGMENTZIP
#include <libfragmentzip/libfragmentzip.h>
#endif //HAVE_LIBFRAGMENTZIP

#define addpatch(pp) do {\
    auto p = pp; \
    patches.insert(patches.end(), p.begin(), p.end()); \
} while (0)

#define addloc(pp) do {\
    patches.push_back({pp,nullptr,0}); \
} while (0)


extern "C" {
#include "jssy.h"
}

#ifdef WITH_IPSW_ME_SUPPORT
#define FIRMWARE_JSON_URL_START "https://firmware-keys.ipsw.me/firmware/"
#define DEVICE_JSON_URL_START   "https://firmware-keys.ipsw.me/device/"
#endif

#define bswap32 __builtin_bswap32

#define IMAGE3_MAGIC 'Img3'
#define IBOOT_VERS_STR_OFFSET 0x286
#define IBOOT32_RESET_VECTOR_BYTES bswap32(0x0E0000EA)


#ifndef HAVE_MEMMEM
void *memmem(const void *haystack_start, size_t haystack_len, const void *needle_start, size_t needle_len){
    const unsigned char *haystack = (const unsigned char *)haystack_start;
    const unsigned char *needle = (const unsigned char *)needle_start;
    const unsigned char *h = nullptr;
    const unsigned char *n = nullptr;
    size_t x = needle_len;

    /* The first occurrence of the empty string is deemed to occur at
    the beginning of the string.  */
    if (needle_len == 0) {
        return (void *)haystack_start;
    }

    /* Sanity check, otherwise the loop might search through the whole
        memory.  */
    if (haystack_len < needle_len) {
        return nullptr;
    }

    for (; *haystack && haystack_len--; haystack++) {
        x = needle_len;
        n = needle;
        h = haystack;

        if (haystack_len < needle_len)
            break;

        if ((*haystack != *needle) || (*haystack + needle_len != *needle + needle_len))
            continue;

        for (; x; h++, n++) {
            x--;

            if (*h != *n)
                break;

            if (x == 0)
                return (void *)haystack;
        }
    }
    return nullptr;
}
#endif


using namespace tihmstar;

namespace tihmstar {
    namespace libipatcher {
        namespace helpers {
            size_t downloadFunction(void* buf, size_t size, size_t nmemb, std::string &data) {
                data.append((char*)buf, size*nmemb);
                return nmemb*size;
            }
            int parseHex(const char *nonce, size_t nonceLen, unsigned char *ret, size_t retSize){
                nonceLen = nonceLen/2 + nonceLen%2; //one byte more if len is odd

                if (!ret) return -3;

                memset(ret, 0, retSize);
                unsigned int nlen = 0;

                int next = strlen(nonce)%2 == 0;
                char tmp = 0;
                while (*nonce && retSize) {
                    char c = *(nonce++);

                    tmp *=16;
                    if (c >= '0' && c<='9') {
                        tmp += c - '0';
                    }else if (c >= 'a' && c <= 'f'){
                        tmp += 10 + c - 'a';
                    }else if (c >= 'A' && c <= 'F'){
                        tmp += 10 + c - 'A';
                    }else{
                        return -1; //ERROR parsing failed
                    }
                    if ((next =! next) && nlen < nonceLen)
                        ret[nlen++] = tmp,tmp=0,retSize--;
                }
                return 0;
            }
        }
        std::string getRemoteFile(std::string url);
        std::string getRemoteDestination(std::string url);
        std::string getFirmwareJson(std::string device, std::string buildnum, uint32_t cpid = 0, std::string boardconfig = "");
        std::string getDeviceJson(std::string device);
#ifdef HAVE_LIBFRAGMENTZIP
        std::string getFirmwareJsonFromZip(std::string device, std::string buildnum, std::string zipURL, uint32_t cpid = 0);
        std::string getDeviceJsonFromZip(std::string device, std::string zipURL);
#endif //HAVE_LIBFRAGMENTZIP

#ifdef WITH_IBOOT32PATCHER
        std::pair<char*,size_t>patchfile32(const char *ibss, size_t ibssSize, const fw_key &keys, std::string findstr, void *param, std::function<int(char *, size_t, void *)> patchfunc);
#endif
#ifdef WITH_IBOOT64PATCHER
        std::pair<char*,size_t>patchfile64(const char *ibss, size_t ibssSize, const fw_key &keys, std::string findstr, void *param, std::function<int(char *, size_t, void *)> patchfunc);
#endif //WITH_IBOOT64PATCHER
    }
}

static inline void hexToInts(const char* hex, unsigned int** buffer, size_t* bytes) {
    *bytes = strlen(hex) / 2;
    *buffer = (unsigned int*) malloc((*bytes) * sizeof(int));
    size_t i;
    for(i = 0; i < *bytes; i++) {
        sscanf(hex, "%2x", &((*buffer)[i]));
        hex += 2;
    }
}

using namespace std;
using namespace libipatcher;
using namespace helpers;

#ifdef WITH_IBOOT32PATCHER
int iBoot32Patch(char *deciboot, size_t decibootSize, void *bootargs) noexcept;
#endif

#ifdef WITH_IBOOT64PATCHER
int kernel64Patch(char *decKernel, size_t decKernelSize, void *args) noexcept;
int iBoot64Patch(char *deciboot, size_t decibootSize, void *args) noexcept;
#endif //WITH_IBOOT64PATCHER


const char *libipatcher::version(){
  return VERSION_STRING;
}

bool libipatcher::has32bitSupport(){
#ifdef WITH_IBOOT32PATCHER
    return true;
#endif //WITH_IBOOT32PATCHER
    return false;
}

bool libipatcher::has64bitSupport(){
#ifdef WITH_IBOOT64PATCHER
    return true;
#endif //WITH_IBOOT64PATCHER
    return false;
}

string libipatcher::getRemoteFile(std::string url){
    string buf;
    CURL *mc = curl_easy_init();
    assure(mc);

    curl_easy_setopt(mc, CURLOPT_URL, url.c_str());
    curl_easy_setopt(mc, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(mc, CURLOPT_USERAGENT, "libipatcher/" VERSION_COMMIT_COUNT " APIKEY=" VERSION_COMMIT_SHA);
    curl_easy_setopt(mc, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(mc, CURLOPT_CONNECTTIMEOUT, 300);
    curl_easy_setopt(mc, CURLOPT_TIMEOUT, 60);

    curl_easy_setopt(mc, CURLOPT_WRITEFUNCTION, &helpers::downloadFunction);
    curl_easy_setopt(mc, CURLOPT_WRITEDATA, &buf);

    assure(curl_easy_perform(mc) == CURLE_OK);
    long http_code = 0;
    curl_easy_getinfo (mc, CURLINFO_RESPONSE_CODE, &http_code);
    assure(http_code == 200);

    curl_easy_cleanup(mc);
    return buf;
}

std::string libipatcher::getRemoteDestination(std::string url){
  char* location = nullptr; //don't free me manually
  string buf;
  uint64_t curlcode = 0;
  CURL *mc = curl_easy_init();
  assure(mc);

  curl_easy_setopt(mc, CURLOPT_URL, url.c_str());
  curl_easy_setopt(mc, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt(mc, CURLOPT_USERAGENT, "libipatcher/" VERSION_COMMIT_COUNT " APIKEY=" VERSION_COMMIT_SHA);
  curl_easy_setopt(mc, CURLOPT_CONNECTTIMEOUT, 300);
  curl_easy_setopt(mc, CURLOPT_TIMEOUT, 60);
  curl_easy_setopt(mc, CURLOPT_NOBODY, 1);

  assure(curl_easy_perform(mc) == CURLE_OK);

  curl_easy_getinfo(mc, CURLINFO_RESPONSE_CODE, &curlcode);
  assure(curlcode < 400);

  assure(curl_easy_getinfo(mc, CURLINFO_REDIRECT_URL, &location) == CURLE_OK);
  buf = location;

  curl_easy_cleanup(mc);
  return buf;
}


string libipatcher::getFirmwareJson(std::string device, std::string buildnum, uint32_t cpid, std::string boardconfig){
    {
      auto *tmp = getenv("LIP_PROXY_URL");
      string url;
      if(!tmp) {
        url = string("https://api.m1sta.xyz/wikiproxy/");
      } else {
        url = string(tmp) + "/wikiproxy/";
      }
      if(boardconfig == "") {
        url += device + "/" + buildnum;
      } else {
        url += device + "/" + boardconfig + "/" + buildnum;
      }
      try {
        return getRemoteFile(url);
      } catch (...) {
        if(tmp) {
          fprintf(stderr, "Failed to connect to LIP_PROXY_URL: %s\n", tmp);
        } else {
          fprintf(stderr, "Failed to connect to api.m1sta.xyz, retrying with localhost!\n");
        }

      }
      free(tmp);
    }

    std::string cpid_str;
    if (cpid) {
      char buf[0x100] = {};
      snprintf(buf, sizeof(buf), "0x%x/", cpid);
      cpid_str = buf;
    }

    {
      //try localhost
      string url("localhost:8888/firmware/");
      url += device + "/";
      if (cpid_str.size()) {
        try {return getRemoteFile(url + cpid_str + buildnum);} catch (...) {}
      }
      try {
        if(boardconfig == "") {
          url += device + "/" + buildnum;
        } else {
          url += device + "/" + boardconfig + "/" + buildnum;
        }
        return getRemoteFile(url);
      } catch (...) {
#ifdef FIRMWARE_JSON_URL_START
        fprintf(stderr, "Failed to connect to localhost, retrying with %s!\n", FIRMWARE_JSON_URL_START);
#else
        fprintf(stderr, "Failed to connect to localhost!\n");
#endif
      }
    }

#ifdef FIRMWARE_JSON_URL_START
    {
        //retrying with api server
        string url(FIRMWARE_JSON_URL_START);
        url += device + "/";

        if (cpid_str.size()) {
            try {return getRemoteFile(url + cpid_str + buildnum);} catch (...) {}
        }
        try {
          return getRemoteFile(url + buildnum);
        } catch (...) {
          fprintf(stderr, "Failed to connect to %s!\n", FIRMWARE_JSON_URL_START);
        }
    }
#endif

    reterror("failed to get FirmwareJson from Server");
}

string libipatcher::getDeviceJson(std::string device){
    try {
        string url("localhost:8888/device/");
        url += device;
        return getRemoteFile(url);
    } catch (...) {
        //retrying with local server
    }

#ifdef DEVICE_JSON_URL_START
    try {
        string url(DEVICE_JSON_URL_START);
        url += device;
        return getRemoteFile(url);
    } catch (...) {
        //fall though and fail
    }
#endif

    reterror("failed to get DeviceJson from Server");
}

#ifdef HAVE_LIBFRAGMENTZIP
std::string libipatcher::getFirmwareJsonFromZip(std::string device, std::string buildnum, std::string zipURL, uint32_t cpid){
    fragmentzip_t *fz = nullptr;
    char *outBuf = nullptr;
    cleanup([&]{
        safeFree(outBuf);
        safeFreeCustom(fz, fragmentzip_close);
    });
    size_t outBufSize = 0;

    std::string cpid_str;
    if (cpid) {
        char buf[0x100] = {};
        snprintf(buf, sizeof(buf), "0x%x/",cpid);

        cpid_str = buf;
    }

    retassure(fz = fragmentzip_open(zipURL.c_str()), "Failed to open zipURL '%s'",zipURL.c_str());

    {
        int err = 0;
        std::string filePath = "firmware/" + device + "/";
        if ((err = fragmentzip_download_to_memory(fz, (filePath + cpid_str + buildnum).c_str(), &outBuf, &outBufSize, nullptr))) {
            err = fragmentzip_download_to_memory(fz, (filePath + buildnum).c_str(), &outBuf, &outBufSize, nullptr);
        }
        retassure(!err, "Failed to get firmware json from zip with err=%d",err);
    }

    return {outBuf,outBuf+outBufSize};
}

string libipatcher::getDeviceJsonFromZip(std::string device, std::string zipURL){
    fragmentzip_t *fz = nullptr;
    char *outBuf = nullptr;
    cleanup([&]{
        safeFree(outBuf);
        safeFreeCustom(fz, fragmentzip_close);
    });
    size_t outBufSize = 0;

    retassure(fz = fragmentzip_open(zipURL.c_str()), "Failed to open zipURL '%s'",zipURL.c_str());

    {
        int err = 0;
        std::string filePath = "firmware/" + device;
        retassure(!(err = fragmentzip_download_to_memory(fz, filePath.c_str(), &outBuf, &outBufSize, nullptr)), "Failed to get firmware json from zip with err=%d",err);
    }

    return {outBuf,outBuf+outBufSize};
}

#endif //HAVE_LIBFRAGMENTZIP


fw_key getFirmwareKeyForComparator(std::string device, std::string buildnum, std::function<bool(const jssytok_t *e)> comparator, uint32_t cpid, std::string boardconfig, std::string zipURL){
    jssytok_t* tokens = nullptr;
    unsigned int * tkey = nullptr;
    unsigned int * tiv = nullptr;
    cleanup([&]{
        safeFree(tiv);
        safeFree(tkey);
        safeFree(tokens);
    });
    fw_key rt = {0};
    long tokensCnt = 0;

#ifdef HAVE_LIBFRAGMENTZIP
    string json = (zipURL.size()) ? getFirmwareJsonFromZip(device, buildnum, zipURL, cpid) : getFirmwareJson(device, buildnum, cpid, boardconfig);
#else
    string json = getFirmwareJson(device, buildnum, cpid, boardconfig);
#endif //HAVE_LIBFRAGMENTZIP

    retassure((tokensCnt = jssy_parse(json.c_str(), json.size(), nullptr, 0)) > 0, "failed to parse json");
    assure(tokens = (jssytok_t*)malloc(sizeof(jssytok_t)*tokensCnt));
    assure(jssy_parse(json.c_str(), json.size(), tokens, tokensCnt * sizeof(jssytok_t)) == tokensCnt);

    jssytok_t *keys = jssy_dictGetValueForKey(tokens, "keys");
    assure(keys);

    jssytok_t *iv = nullptr;
    jssytok_t *key = nullptr;
    jssytok_t *path = nullptr;

    jssytok_t *tmp = keys->subval;
    for (size_t i=0; i<keys->size; tmp=tmp->next, i++) {
        if (comparator(tmp)){
            iv = jssy_dictGetValueForKey(tmp, "iv");
            key = jssy_dictGetValueForKey(tmp, "key");
            path = jssy_dictGetValueForKey(tmp, "filename");
            break;
        }
    }
    assure(iv && key);

    assure(iv->size <= sizeof(rt.iv));
    assure(key->size <= sizeof(rt.key));
    memcpy(rt.iv, iv->value, iv->size);
    memcpy(rt.key, key->value, key->size);
    rt.iv[sizeof(rt.iv)-1] = 0;
    rt.key[sizeof(rt.key)-1] = 0;

    if (path) rt.pathname = {path->value,path->value+path->size};

    {
        size_t bytes;
        hexToInts(rt.iv, &tiv, &bytes);
        retassure(bytes == 16 || bytes == 0, "IV has bad length. Expected=16 actual=%lld. Got IV=%s",bytes,rt.iv);
        if (!bytes) memset(rt.iv, 0, sizeof(rt.iv)); //indicate no key required
        hexToInts(rt.key, &tkey, &bytes);
        retassure(bytes == 32  || bytes == 16 || bytes == 0, "KEY has bad length. Expected 32 or 16 actual=%lld. Got KEY=%s",bytes,rt.key);
        if (!bytes) memset(rt.key, 0, sizeof(rt.key)); //indicate no key required
    }
    return rt;
}


fw_key libipatcher::getFirmwareKeyForComponent(std::string device, std::string buildnum, std::string component, uint32_t cpid, std::string boardconfig, std::string zipURL){
    if (component == "RestoreLogo")
        component = "AppleLogo";
    else if (component == "RestoreRamDisk")
        component = "RestoreRamdisk";
    else if (component == "RestoreDeviceTree")
        component = "DeviceTree";
    else if (component == "RestoreKernelCache")
        component = "Kernelcache";

    return getFirmwareKeyForComparator(device, buildnum, [&component](const jssytok_t *e){
        jssytok_t *image = jssy_dictGetValueForKey(e, "image");
        assure(image);
        return strncmp(component.c_str(), image->value, image->size) == 0;
    }, cpid, boardconfig, zipURL);
}

fw_key libipatcher::getFirmwareKeyForPath(std::string device, std::string buildnum, std::string path, uint32_t cpid, std::string boardconfig, std::string zipURL){
    return getFirmwareKeyForComparator(device, buildnum, [&path](const jssytok_t *e){
        jssytok_t *filename = jssy_dictGetValueForKey(e, "filename");
        assure(filename);
        return strncmp(path.c_str(), filename->value, filename->size) == 0;
    }, cpid, boardconfig, zipURL);
}

#ifdef WITH_IBOOT32PATCHER
pair<char*,size_t>libipatcher::patchfile32(const char *ibss, size_t ibssSize, const fw_key &keys, string findstr, void *param, function<int(char *, size_t, void*)> patchfunc){
    char *patched = nullptr;
    const char *key_iv = nullptr;
    const char *key_key = nullptr;
    const char *usedCompression = nullptr;

    //if one single byte isn't \x00 then set the iv
    for (int i=0; i<sizeof(keys.iv); i++) {
        if (keys.iv[i]){
            key_iv = keys.iv;
            break;
        }
    }

    //if one single byte isn't \x00 then set the key
    for (int i=0; i<sizeof(keys.key); i++) {
        if (keys.key[i]){
            key_key = keys.key;
            break;
        }
    }

    auto payload = img3tool::getPayloadFromIMG3(ibss, ibssSize, key_iv, key_key, &usedCompression);

    if (findstr.size()){
        //check if decryption was successfull
        retassure(memmem(payload.data(), payload.size(), findstr.c_str() , findstr.size()), "Failed to find '%s'. Assuming decryption failed!",findstr.c_str());
    }
    //patch here
    if (patchfunc) {
        assure(!patchfunc((char*)payload.data(), payload.size(), param));
    }

    auto newpayload = img3tool::replaceDATAinIMG3({ibss,ibssSize}, payload, usedCompression);
    newpayload = img3tool::removeTagFromIMG3(newpayload.data(), newpayload.size(), 'KBAG');

    patched = (char*)malloc(newpayload.size());
    memcpy(patched, newpayload.data(), newpayload.size());

    return {patched,newpayload.size()};
}
#endif

#ifdef WITH_IBOOT64PATCHER
std::pair<char*,size_t> libipatcher::patchfile64(const char *ibss, size_t ibssSize, const fw_key &keys, std::string findstr, void *param, std::function<int(char *, size_t, void *)> patchfunc){
  char *patched = nullptr;
  const char *key_iv = nullptr;
  const char *key_key = nullptr;
  const char *usedCompression = nullptr;
  img4tool::ASN1DERElement hypervisor{{img4tool::ASN1DERElement::TagNULL,img4tool::ASN1DERElement::Primitive,img4tool::ASN1DERElement::Universal},nullptr,0};

  //if one single byte isn't \x00 then set the iv
  for (int i=0; i<sizeof(key_iv); i++) {
    if (keys.iv[i]){
      key_iv = keys.iv;
      break;
    }
  }

  //if one single byte isn't \x00 then set the key
  for(int i=0; i<sizeof(key_key); i++) {
    if (keys.key[i]){
      key_key = keys.key;
      break;
    }
  }

  img4tool::ASN1DERElement im4p(ibss,ibssSize);

  img4tool::ASN1DERElement payload = getPayloadFromIM4P(im4p, key_iv, key_key, &usedCompression, &hypervisor);

  if (findstr.size()){
    //check if decryption was successfull
    retassure(memmem(payload.payload(), payload.payloadSize(), findstr.c_str() , findstr.size()), "Failed to find '%s'. Assuming decryption failed!",findstr.c_str());
  }

  assure(payload.ownsBuffer());

  //patch here
  if (patchfunc) {
    assure(!patchfunc((char*)payload.payload(), payload.payloadSize(), param));
  }

  img4tool::ASN1DERElement patchedIM4P = img4tool::getEmptyIM4PContainer(im4p[1].getStringValue().c_str(), im4p[2].getStringValue().c_str());

  {
#warning BUG WORKAROUND recompressing images with bvx2 makes them not boot for some reason
    if (usedCompression && strcmp(usedCompression, "bvx2") == 0) {
      warning("BUG WORKAROUND recompressing images with bvx2 makes them not boot for some reason. Skipping compression");
      usedCompression = nullptr;
    }
  }

  patchedIM4P = img4tool::appendPayloadToIM4P(patchedIM4P, payload.payload(), payload.payloadSize(), usedCompression, hypervisor.payload(), hypervisor.payloadSize());

  patched = (char*)malloc(patchedIM4P.size());
  memcpy(patched, patchedIM4P.buf(), patchedIM4P.size());

  return {patched,patchedIM4P.size()};
}
#endif //WITH_IBOOT64PATCHER


#ifdef WITH_IBOOT32PATCHER
int iBoot32Patch(char *deciboot, size_t decibootSize, void *bootargs_) noexcept{
    patchfinder::ibootpatchfinder32 *ibpf = nullptr;
    cleanup([&]{
        if (ibpf) {
            delete ibpf;
        }
    });
    const char *bootargs = (const char*)bootargs_;
    std::vector<patchfinder::patch> patches;

    printf("%s: Staring iBoot32Patch!\n", __FUNCTION__);
    try {
        ibpf = patchfinder::ibootpatchfinder32::make_ibootpatchfinder32(deciboot,decibootSize);
    } catch (...) {
        printf("%s: Failed initing ibootpatchfinder32!\n", __FUNCTION__);
        return -(__LINE__);
    }
    printf("%s: Inited ibootpatchfinder32!\n", __FUNCTION__);

    try { //do sigpatches
        auto patch = ibpf->get_sigcheck_patch();
        patches.insert(patches.end(), patch.begin(), patch.end());
    } catch (...) {
        printf("%s: Failed getting sigpatches!\n", __FUNCTION__);
        return -(__LINE__);
    }
    printf("%s: Added sigpatches!\n", __FUNCTION__);

    if (ibpf->has_kernel_load()) {
        printf("%s: has_kernel_load is true!\n", __FUNCTION__);

        try { //do debugenabled patch
            auto patch = ibpf->get_debug_enabled_patch();
            patches.insert(patches.end(), patch.begin(), patch.end());
        } catch (...) {
            printf("%s: Failed getting debugenabled patch!\n", __FUNCTION__);
            return -(__LINE__);
        }
        printf("%s: Added debugenabled patch!\n", __FUNCTION__);

        if (bootargs) {
            try { //do bootarg patches
                auto patch = ibpf->get_boot_arg_patch(bootargs);
                patches.insert(patches.end(), patch.begin(), patch.end());
            } catch (...) {
                printf("%s: Failed getting bootarg patch!\n", __FUNCTION__);
                return -(__LINE__);
            }
            printf("%s: Added bootarg patch!\n", __FUNCTION__);
        }
    }else{
        printf("%s: has_kernel_load is false!\n", __FUNCTION__);
    }

    for (auto p : patches) {
        uint64_t off = (uint64_t)(p._location - ibpf->find_base());
        printf("%s: Applying patch=%p : ",__FUNCTION__,(void*)p._location);
        for (int i=0; i<p._patchSize; i++) {
            printf("%02x",((uint8_t*)p._patch)[i]);
        }
        printf("\n");
        memcpy(&deciboot[off], p._patch, p._patchSize);
    }

    printf("%s: Patches applied!\n", __FUNCTION__);

    return 0;
}
#endif

#ifdef WITH_IBOOT64PATCHER

int kernel64Patch(char *decKernel, size_t decKernelSize, void *args) noexcept{
  patchfinder::kernelpatchfinder *kpf = nullptr;
  cleanup([&]{
    if(kpf) {
      delete kpf;
    }
  });
  const char *custom_seed = (const char*)args;
  std::vector<patchfinder::patch> patches;
  printf("%s: Starting...\n", __FUNCTION__);
  try {
    kpf = patchfinder::kernelpatchfinder64::make_kernelpatchfinder64(decKernel,decKernelSize);
  } catch (...) {
    printf("%s: Failed initializing kernel!\n", __FUNCTION__);
    return -(__LINE__);
  }
  printf("%s: Initialized kernel!\n", __FUNCTION__);
  std::string version = kpf->get_xnu_kernel_version_number_string();
  if(!version.empty()) {
    uint32_t vers = atoi(version.c_str());
    if(vers > 8700) {
      try {
        if(custom_seed && strlen(custom_seed) >= 32) {
          uint8_t *seed = nullptr;
          if(memcmp(custom_seed, "0x", 2) == 0) {
            if(strlen(custom_seed) - 2 < 32) {
              printf("%s: Failed getting cryptexseed patch: %s!\n", __FUNCTION__, !custom_seed ? "0x11111111111111111111111111111111" : custom_seed);
              return -__LINE__;
            }
            custom_seed+=2;
          }
          size_t cnt;
          uint32_t *tmp = nullptr;
          hexToInts(custom_seed, &tmp, &cnt);
          if(cnt != 16) {
            printf("%s: Failed getting cryptexseed patch: %s! (%s)\n", __FUNCTION__, !custom_seed ? "0x11111111111111111111111111111111" : custom_seed);
            return -__LINE__;
          }
          seed = (uint8_t *)tmp;
//          uint8_t tmp[50];
//          memcpy(&tmp[0] + 0, custom_seed + 0, 16); *(uint8_t *)(&tmp[0] + 16) = '\0';
//          memcpy(&tmp[0] + 17, custom_seed + 16, 16); *(uint8_t *)(&tmp[0] + 34) = '\0';
//          *(uint64_t *)(seed + 0) = strtol((const char *)&tmp[0], nullptr, 16);
//          *(uint64_t *)(seed + 8) = strtol((const char *)&tmp[0] + 17, nullptr, 16);
          kpf->get_img4_nonce_manager_generate_seed_patch(seed);
          addpatch(kpf->get_img4_nonce_manager_generate_seed_patch(seed));
        } else {
          addpatch(kpf->get_img4_nonce_manager_generate_seed_patch(nullptr));
        }
      } catch (tihmstar::exception &e) {
        printf("%s: Failed getting cryptexseed patch: %s! (%s)\n", __FUNCTION__, !custom_seed ? "0x11111111111111111111111111111111" : custom_seed, e.what());
        return -__LINE__;
      }
    }
    printf("%s: Added cryptexseed patch!\n", __FUNCTION__);
  }
  for (const auto& p2 : patches) {
    printf("%s: Applying patch=0x%016llx: ", __FUNCTION__, p2._location);
    for (int i=0; i<p2._patchSize; i++) {
      printf("%02x",((uint8_t*)p2._patch)[i]);
    }
    if (p2._patchSize == 4) {
      printf(" 0x%08x",*(uint32_t*)p2._patch);
    } else if (p2._patchSize == 2) {
      printf(" 0x%04x",*(uint16_t*)p2._patch);
    }
    printf("\n");
    uint64_t base = 0;
    uint64_t off = 0;
    off = (uint64_t)((const char *)kpf->memoryForLoc(p2._location) - decKernel);
    memcpy(&decKernel[off], p2._patch, p2._patchSize);
  }
  printf("%s: Patches applied!\n", __FUNCTION__);
  return 0;
}

int iBoot64Patch(char *deciboot, size_t decibootSize, void *args) noexcept {
  patchfinder::ibootpatchfinder *ibpf = nullptr;
  cleanup([&]{
      if (ibpf) {
          delete ibpf;
      }
  });
  const char *bootargs = (const char*)args;
  std::vector<patchfinder::patch> patches;

  printf("%s: Starting...\n", __FUNCTION__);
  try {
      ibpf = patchfinder::ibootpatchfinder64::make_ibootpatchfinder64(deciboot,decibootSize);
  } catch (...) {
    printf("%s: Failed initializing iBoot!\n", __FUNCTION__);
    return -(__LINE__);
  }
  printf("%s: Initialized iBoot!\n", __FUNCTION__);

  try { //do sigpatches
    auto patch = ibpf->get_sigcheck_patch();
    patches.insert(patches.end(), patch.begin(), patch.end());
  } catch (...) {
    printf("%s: Failed getting sigpatches!\n", __FUNCTION__);
    return -(__LINE__);
  }
  printf("%s: Added sigpatches!\n", __FUNCTION__);

  try { //do freshnonce patch
    auto patch = ibpf->get_freshnonce_patch();
    patches.insert(patches.end(), patch.begin(), patch.end());
  } catch (...) {
    printf("%s: Failed getting freshnonce patch!\n", __FUNCTION__);
    return -(__LINE__);
  }
  printf("%s: Added freshnonce patch!\n", __FUNCTION__);

  try { //do unlock nvram patch
    auto patch = ibpf->get_unlock_nvram_patch();
    patches.insert(patches.end(), patch.begin(), patch.end());
  } catch (...) {
    printf("%s: Failed getting unlock nvram patch!\n", __FUNCTION__);
    return -(__LINE__);
  }
  printf("%s: Added unlock nvram patch!\n", __FUNCTION__);

  if(ibpf->has_kernel_load()) {
    try { //do debugenabled patch
      auto patch = ibpf->get_debug_enabled_patch();
      patches.insert(patches.end(), patch.begin(), patch.end());
    } catch (...) {
      printf("%s: Failed getting debugenabled patch!\n", __FUNCTION__);
      return -(__LINE__);
    }
    printf("%s: Added debugenabled patch!\n", __FUNCTION__);
    if(bootargs && strlen(bootargs) > 0) {
      try { // do bootarg patches
        auto patch = ibpf->get_boot_arg_patch(bootargs);
        patches.insert(patches.end(), patch.begin(), patch.end());
      } catch (...) {
        printf("%s: Failed getting bootarg patch!\n", __FUNCTION__);
        return -(__LINE__);
      }
      printf("%s: Added bootarg patch!\n", __FUNCTION__);
    }
  } else {
    printf("%s: has_kernel_load is false!\n", __FUNCTION__);
  }

  for (auto p : patches) {
    uint64_t off = (uint64_t)(p._location - ibpf->find_base());
    printf("%s: Applying patch=%p : ",__FUNCTION__,(void*)p._location);
    for (int i=0; i<p._patchSize; i++) {
      printf("%02x",((uint8_t*)p._patch)[i]);
    }
    printf("\n");
    memcpy(&deciboot[off], p._patch, p._patchSize);
  }
  printf("%s: Patches applied!\n", __FUNCTION__);

  return 0;
}
#endif //WITH_IBOOT64PATCHER

pair<char*,size_t>libipatcher::patchiBSS(const char *ibss, size_t ibssSize, const fw_key &keys){
#ifdef WITH_IBOOT64PATCHER
    bool is64Bit = false;
    try {
       img4tool::ASN1DERElement im4p(ibss,ibssSize);
       if (img4tool::isIM4P(im4p)) {
           is64Bit = true;
       }
    } catch (...) {
       //
    }
    if (is64Bit) {
        return patchfile64(ibss, ibssSize, keys, "iBoot", nullptr, iBoot64Patch);
    }
#endif //WITH_IBOOT64PATCHER

#ifdef WITH_IBOOT32PATCHER
    return patchfile32(ibss, ibssSize, keys, "iBoot", nullptr, iBoot32Patch);
#endif
    reterror("No compatible backend available!");
}



pair<char*,size_t>libipatcher::patchiBEC(const char *ibec, size_t ibecSize, const libipatcher::fw_key &keys, std::string bootargs){
#ifdef WITH_IBOOT64PATCHER
    bool is64Bit = false;
    try {
        img4tool::ASN1DERElement im4p(ibec,ibecSize);
        if (img4tool::isIM4P(im4p)) {
            is64Bit = true;
        }
    } catch (...) {
        //
    }

    if (is64Bit) {
        return patchfile64(ibec, ibecSize, keys, "iBoot", (void*)(bootargs.size() ? bootargs.c_str() : nullptr), iBoot64Patch);
    }
#endif //WITH_IBOOT64PATCHER

#ifdef WITH_IBOOT32PATCHER
    return patchfile32(ibec, ibecSize, keys, "iBoot", (void*)(bootargs.size() ? bootargs.c_str() : nullptr), iBoot32Patch);
#endif
    reterror("No compatible backend available!");
}

pair<char*,size_t>libipatcher::patchKernel(const char *kernel, size_t kernelSize, const libipatcher::fw_key &keys, std::string custom_seed){
#ifdef WITH_IBOOT64PATCHER
  bool is64Bit = false;
  try {
    img4tool::ASN1DERElement im4p(kernel,kernelSize);
    if (img4tool::isIM4P(im4p)) {
      is64Bit = true;
    }
  } catch (...) {
    //
  }

  if (is64Bit) {
    return patchfile64(kernel, kernelSize, keys, "KernelCache", (void*)(custom_seed.size() ? custom_seed.c_str() : nullptr), kernel64Patch);
  }
#endif //WITH_IBOOT64PATCHER

//#ifdef WITH_IBOOT32PATCHER
//  return patchfile32(kernel, kernelSize, keys, "iBoot", (void*)(bootargs.size() ? bootargs.c_str() : nullptr), iBoot32Patch);
//#endif
  reterror("No compatible backend available!");
}

std::pair<char*,size_t>libipatcher::patchCustom(const char *file, size_t fileSize, const fw_key &keys, std::function<int(char *, size_t, void *)> patchfunc, void *parameter, std::string findDecStr){
#ifdef WITH_IBOOT64PATCHER
    bool is64Bit = false;
    try {
        img4tool::ASN1DERElement im4p(file,fileSize);
        if (img4tool::isIM4P(im4p)) {
            is64Bit = true;
        }
    } catch (...) {
        //
    }

    if (is64Bit) {
        return patchfile64(file, fileSize, keys, findDecStr, parameter, patchfunc);
    }
#endif //WITH_IBOOT64PATCHER

#ifdef WITH_IBOOT32PATCHER
    return patchfile32(file, fileSize, keys, findDecStr, parameter, patchfunc);
#endif
    reterror("No compatible backend available!");
}

std::pair<char*,size_t> libipatcher::decryptFile(const char *fbuf, size_t fbufSize, const fw_key &keys){
    return patchCustom(fbuf, fbufSize, keys, nullptr, nullptr, {});
}

std::pair<char*,size_t>libipatcher::packIM4PToIMG4(const void *im4p, size_t im4pSize, const void *im4m, size_t im4mSize){
#ifdef HAVE_IMG4TOOL
  char *out = nullptr;
  img4tool::ASN1DERElement eim4p{im4p,im4pSize};
  img4tool::ASN1DERElement eim4m{im4m,im4mSize};

  img4tool::ASN1DERElement img4 = img4tool::getEmptyIMG4Container();

  img4 = img4tool::appendIM4PToIMG4(img4, eim4p);
  img4 = img4tool::appendIM4MToIMG4(img4, eim4m);

  out = (char*)malloc(img4.size());
  memcpy(out, img4.buf(), img4.size());
  return {out,img4.size()};
#else
  reterror("Compiled without img4tool!");
#endif //HAVE_IMG4TOOL
}


pwnBundle libipatcher::getPwnBundleForDevice(std::string device, std::string buildnum, uint32_t cpid, std::string boardconfig, std::string zipURL){
    jssytok_t* tokens = nullptr;
    cleanup([&]{
        safeFree(tokens);
    });
    long tokensCnt = 0;

    auto getKeys = [cpid,boardconfig,zipURL](std::string device, std::string curbuildnum)->pwnBundle{
        pwnBundle rt;
#ifdef WITH_IPSW_ME_SUPPORT
        string firmwareUrl = "https://api.ipsw.me/v2.1/";
        firmwareUrl += device;
        firmwareUrl += "/";
        firmwareUrl += curbuildnum;
        firmwareUrl += "/url/dl";

        try{
            rt.firmwareUrl = getRemoteDestination(firmwareUrl);
        }catch(...){
            error("failed to get firmware url");
        }
#endif
        rt.iBSSKey = getFirmwareKeyForComponent(device, curbuildnum, "iBSS", cpid, boardconfig, zipURL);
        rt.iBECKey = getFirmwareKeyForComponent(device, curbuildnum, "iBEC", cpid, boardconfig, zipURL);
        return rt;
    };

    if (buildnum.size()) { //if buildnum is given, try to get keys once. error is fatal.
      return getKeys(device,buildnum);
    }

#ifdef HAVE_LIBFRAGMENTZIP
    string json = (zipURL.size()) ? getDeviceJsonFromZip(device, zipURL) : getDeviceJson(device);
#else
    string json = getDeviceJson(device);
#endif //HAVE_LIBFRAGMENTZIP

    assure((tokensCnt = jssy_parse(json.c_str(), json.size(), nullptr, 0)) > 0);
    assure(tokens = (jssytok_t*)malloc(sizeof(jssytok_t)*tokensCnt));
    assure(jssy_parse(json.c_str(), json.size(), tokens, tokensCnt * sizeof(jssytok_t)) == tokensCnt);

    assure(tokens->type == JSSY_ARRAY);

    jssytok_t *tmp = tokens->subval;
    for (size_t i=0; i<tokens->size; tmp=tmp->next, i++) {
      jssytok_t *deviceName = jssy_dictGetValueForKey(tmp, "identifier");
      assure(deviceName && deviceName->type == JSSY_STRING);
      if (strncmp(deviceName->value, device.c_str(), deviceName->size))
        continue;
      jssytok_t *buildID = jssy_dictGetValueForKey(tmp, "buildid");

      string curbuildnum = string(buildID->value,buildID->size);

      //if we are interested in *any* bundle, ignore errors until we run out of builds.
      try {
        return getKeys(device,curbuildnum);
      } catch (...) {
        continue;
      }
    }

    reterror("Failed to create pwnBundle for device=%s buildnum=%s",device.c_str(),buildnum.size() ? buildnum.c_str() : "any");
    return {};
}