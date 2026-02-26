<?php

namespace Pex;

class BaseClient extends Fingerprinter
{
    public function __construct(int $searchType, string $clientID, string $clientSecret)
    {
        $defer = new Defer();

        $initStatusCode = Lib::get()->new("int");
        $initStatusMessage = Lib::get()->new("char[100]");

        Lib::get()->Pex_Init(
            $clientID,
            $clientSecret,
            \FFI::addr($initStatusCode),
            $initStatusMessage,
            \FFI::sizeof($initStatusMessage)
        );

        if ($initStatusCode->cdata != StatusCode::OK) {
            throw new Error(\FFI::string($initStatusMessage), $initStatusCode->cdata);
        }

        Lib::get()->Pex_Lock();
        $defer->add(Lib::get()->Pex_Unlock);

        $status = Lib::get()->Pex_Status_New();
        Error::checkMemory($status);
        $defer->add(fn () => Lib::get()->Pex_Status_Delete(\FFI::addr($status)));

        $this->client = Lib::get()->Pex_Client_New();
        Error::checkMemory($this->client);

        Lib::get()->Pex_Client_Init($this->client, $searchType, $clientID, $clientSecret, $status);
        Error::checkStatus($status, function () use ($defer) {
            Lib::get()->Pex_Client_Delete(\FFI::addr($this->client));
        });
    }

    public function __destruct()
    {
        Lib::get()->Pex_Lock();
        Lib::get()->Pex_Client_Delete(\FFI::addr($this->client));
        Lib::get()->Pex_Unlock();

        Lib::get()->Pex_Cleanup();
    }

    protected function internalStartSearch(PexSearchRequest|ISRCSearchRequest|PrivateSearchRequest $req): SearchFuture
    {
        $defer = new Defer();

        Lib::get()->Pex_Lock();
        $defer->add(Lib::get()->Pex_Unlock);

        $startReq = Lib::get()->Pex_StartSearchRequest_New();
        Error::checkMemory($startReq);
        $defer->add(fn () => Lib::get()->Pex_StartSearchRequest_Delete(\FFI::addr($startReq)));

        $startRes = Lib::get()->Pex_StartSearchResult_New();
        Error::checkMemory($startRes);
        $defer->add(fn () => Lib::get()->Pex_StartSearchResult_Delete(\FFI::addr($startRes)));

        $status = Lib::get()->Pex_Status_New();
        Error::checkMemory($status);
        $defer->add(fn () => Lib::get()->Pex_Status_Delete(\FFI::addr($status)));
        
        if ($req instanceof ISRCSearchRequest) {
            Lib::get()->Pex_StartSearchRequest_SetISRC(
                $startReq, $req->getISRC(), Fingerprinter::convertTypes($req->getFTTypes()));
        } else if ($req instanceof PrivateSearchRequest || $req instanceof PexSearchRequest) {
            $buffer = Lib::get()->Pex_Buffer_New();
            Error::checkMemory($buffer);
            $defer->add(fn () => Lib::get()->Pex_Buffer_Delete(\FFI::addr($buffer)));

            $ft = $req->getFingerprint();
            Lib::get()->Pex_Buffer_Set($buffer, $ft->getBytes(), strlen($ft->getBytes()));

            Lib::get()->Pex_StartSearchRequest_SetFingerprint($startReq, $buffer, $status);
            Error::checkStatus($status);
        }

        if ($req instanceof PexSearchRequest || $req instanceof ISRCSearchRequest) {
            Lib::get()->Pex_StartSearchRequest_SetType($startReq, $req->getType());
        }

        Lib::get()->Pex_StartSearch($this->client, $startReq, $startRes, $status);
        Error::checkStatus($status);

        $lookupIDs = [];

        $lookupID = Lib::get()->new("char*");
        $idx = Lib::get()->new("size_t");
        $idx->cdata = 0;

        while (Lib::get()->Pex_StartSearchResult_NextLookupID($startRes, \FFI::addr($idx), \FFI::addr($lookupID))) {
            $lookupIDs[] = \FFI::string($lookupID);
        }

        return new SearchFuture($this, $lookupIDs);
    }

    public function checkSearch(array $lookupIDs): \stdClass
    {
        $defer = new Defer();

        Lib::get()->Pex_Lock();
        $defer->add(Lib::get()->Pex_Unlock);

        $checkReq = Lib::get()->Pex_CheckSearchRequest_New();
        Error::checkMemory($checkReq);
        $defer->add(fn () => Lib::get()->Pex_CheckSearchRequest_Delete(\FFI::addr($checkReq)));

        $checkRes = Lib::get()->Pex_CheckSearchResult_New();
        Error::checkMemory($checkRes);
        $defer->add(fn () => Lib::get()->Pex_CheckSearchResult_Delete(\FFI::addr($checkRes)));

        $status = Lib::get()->Pex_Status_New();
        Error::checkMemory($status);
        $defer->add(fn () => Lib::get()->Pex_Status_Delete(\FFI::addr($status)));

        foreach ($lookupIDs as $lookupID) {
            Lib::get()->Pex_CheckSearchRequest_AddLookupID($checkReq, $lookupID);
        }

        Lib::get()->Pex_CheckSearch($this->client, $checkReq, $checkRes, $status);
        Error::checkStatus($status);

        $json = Lib::get()->Pex_CheckSearchResult_GetJSON($checkRes);
        $dec = json_decode($json);

        $dec->lookup_ids = $lookupIDs;
        return $dec;
    }
}
