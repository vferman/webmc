{-
Project: WebMC: a model checker for the web
Author: Victor Ferman
File: Server.hs
Description: This file defines a generic server's actions an capabilities,
    used in order to process requests and responses as a server would, will
    output Responses to each received Request
-}

module Server where

import qualified Data.Map   as Map
import           Data.Maybe
import           Types
import Debug.Trace


{-
    Functions in charge of instantiating servers and of getting the actions
    that can be performed at any given time useful for the Planner
-}

getServerActions :: Server -> [String]
getServerActions = serverActions

initServer :: String -> [String] -> Map.Map Domain Known -> Map.Map Nonce Known -> Map.Map Url [([String], [ServerRule], Response)] ->
  Map.Map Nonce [ServerRule] -> Map.Map Nonce (Nonce, Request) ->
  Map.Map Nonce Response -> [Int] -> Server
initServer sID genData serverData sessionData rules pReq eRes pRes nonceL =
    Server {serverIdentifier = sID, autoGenerated = genData,
      serverKnowledge = serverData, serverSession = sessionData,
      serverRules = rules, pendingSRequests = pReq, expectedResponses = eRes,
      pendingSResponses = pRes, sNonceList = nonceL}

initEmptyServer :: String -> [String] ->
  Map.Map Url [([String], [ServerRule], Response)] -> Server
initEmptyServer sID genData rules = initServer sID genData Map.empty Map.empty
  rules Map.empty Map.empty Map.empty [1..]


errorResponse :: String -> Url -> Nonce -> Response
errorResponse bid url nonc =
    Response { destinationIdentifier = bid, origin = url, resNonce = nonc,
       csp = Csp { scriptList = [], frameList = [], resourceList = []},
       componentList =[], instructionList = PageInstructions { autoList = [],
         conditionalList = []}, fileList = Map.empty}

compliesWithSRule:: Known -> [String] -> Bool
compliesWithSRule _ []= True
compliesWithSRule knowledge requirements = all (`Map.member` knowledge) requirements

getRule:: Known -> [([String], [ServerRule], Response)] -> Maybe ([ServerRule],Response)
getRule _ [] = Nothing
getRule knowledge (x:xs)
    | compliesWithSRule knowledge requirements = Just (sReqRules, response)
    | otherwise = getRule knowledge xs
    where (requirements, sReqRules, response) = x

requestReceived:: Server -> Request -> Server
requestReceived cServer request =
    Server { serverIdentifier = sID, autoGenerated = auto,
      serverKnowledge = sKnown,
      serverSession = Map.insert rNonce sessionInfo sSession,
      serverRules = sRules,
      pendingSRequests = Map.insert rNonce ruleRequests sPReq,
      expectedResponses= eSResp,
      pendingSResponses = Map.insert rNonce ruleResponse spRes,
      sNonceList= sNL }
    where (Server { serverIdentifier = sID, autoGenerated = auto,
            serverKnowledge = sKnown, serverSession = sSession,
            serverRules = sRules, pendingSRequests = sPReq,
            expectedResponses= eSResp, pendingSResponses = spRes,
            sNonceList= sNL }) = cServer
          (Request { originIdentifier = bID, destination = dUrl,
            reqNonce = rNonce, payload = reqInfo }) = request
          validUrl = Map.lookup dUrl sRules
          validRule = maybe Nothing (getRule reqInfo) validUrl
          requestExtraInfo = Map.fromList [("dID", bID), ("dUrl", show dUrl)]
          sessionInfo = Map.union requestExtraInfo reqInfo
          (ruleRequests, ruleResponse) = fromMaybe ([], errorResponse bID dUrl
            rNonce) validRule

getRequestRule:: [ServerRule] -> Maybe ServerRule
getRequestRule [] = Nothing
getRequestRule (x:_) = Just x

getKnownElems :: Maybe Known -> [String] -> Known
getKnownElems _ [] = Map.empty
getKnownElems Nothing _ = Map.empty
getKnownElems (Just known) list = Map.fromList result
    where elems = filter (`Map.member` known) list
          result = map (\y ->  (y, known Map.! y)) elems

genAutoElem :: Nonce -> [String] -> [String] -> Known
genAutoElem _ [] _ = Map.empty
genAutoElem _ _ [] = Map.empty
genAutoElem nonce auto list = Map.fromList result
    where elems = filter (`elem` auto) list
          result = map (\y -> (y, y++ nonce)) elems


requestFromRule :: String -> Int -> Map.Map Domain Known -> Maybe Known->
  [String] -> Maybe ServerRule -> Maybe Request
requestFromRule _ _ _ _ _ Nothing = Nothing
requestFromRule sID nonce know kInfo auto rule
    | isJust reqUrl && all (`elem` Map.keys rPayload) ruleContent =
        Just Request { originIdentifier = sID, destination = fromJust reqUrl,
          reqNonce = newNonce, method = ruleMethod, payload =rPayload }
    | otherwise = Nothing
    where (Just ServerRule { sReqMethod= ruleMethod, sReqUrl = ruleDest,
            sReqContents = ruleContent }) = rule
          info = fromMaybe Map.empty kInfo
          reqUrl = either Just (\b -> maybe Nothing (\s -> Just (read s))
                     (Map.lookup b info)) ruleDest
          newNonce = "nonce"++sID ++ show nonce
          contentKnown = getKnownElems (Map.lookup (maybeUrlDomain reqUrl) know) ruleContent
          contentInfo = getKnownElems kInfo ruleContent
          autoInfo = genAutoElem newNonce auto ruleContent
          rPayload = Map.union autoInfo $ Map.union contentKnown contentInfo

sendRequest::Server -> Nonce -> (Server, Maybe Request)
sendRequest cServer nonce
    | isJust generatedRequest = (Server { serverIdentifier = sID,
        autoGenerated = auto, serverKnowledge = sKnown,
        serverSession = sSession, serverRules = sRules,
        pendingSRequests = Map.insert nonce (tail (fromJust ruleList)) sPReq,
        expectedResponses= Map.insert (sID ++ show (head sNL))
          (nonce, fromJust generatedRequest) eSResp,
        pendingSResponses = spRes, sNonceList= tail sNL },
        generatedRequest)
    | otherwise = (Server { serverIdentifier = sID, autoGenerated = auto,
        serverKnowledge = sKnown, serverSession = sSession,
        serverRules = sRules, pendingSRequests = Map.delete nonce sPReq,
        expectedResponses= Map.delete nonce eSResp,
        pendingSResponses = Map.insert nonce eResponse spRes, sNonceList= sNL }, Nothing)
    where (Server { serverIdentifier = sID, autoGenerated = auto,
            serverKnowledge = sKnown, serverSession = sSession,
            serverRules = sRules, pendingSRequests = sPReq,
            expectedResponses= eSResp, pendingSResponses = spRes,
            sNonceList= sNL }) = cServer
          ruleList = Map.lookup nonce sPReq
          rule = maybe Nothing getRequestRule ruleList
          reqKnowledge = Map.lookup nonce sSession
          generatedRequest = requestFromRule sID (head sNL) sKnown
            reqKnowledge auto rule
          bID =  fromMaybe Map.empty reqKnowledge Map.! "dID"
          dUrl = read (fromMaybe Map.empty reqKnowledge Map.! "dUrl")
          eResponse = errorResponse bID dUrl nonce

expectedResponse:: Request -> Response -> Bool
expectedResponse request response
    | oID == dID && dUrl == oUrl && sentNonce == recNonce = True
    | otherwise = False
    where (Request { originIdentifier = oID, destination = dUrl,
            reqNonce = sentNonce}) = request
          (Response { destinationIdentifier = dID, origin = oUrl,
            resNonce = recNonce}) = response

fileContents :: WebFile -> Known
fileContents file = contents
    where (WebFile { fContent = contents })= file

urlDomain :: Url -> Domain
urlDomain url = domain
    where (Url{ server= domain }) = url

maybeUrlDomain :: Maybe Url -> Domain
maybeUrlDomain Nothing = ""
maybeUrlDomain (Just url) = domain
    where (Url{ server= domain }) = url

filesToShared:: Map.Map Url WebFile -> Map.Map Domain Known
filesToShared recFiles
    | recFiles /= Map.empty =
        Map.mapKeys urlDomain $ Map.map fileContents recFiles
    | otherwise = Map.empty

instructionToRule:: Instruction -> (Known, Maybe ServerRule)
instructionToRule instruction
    | validUrl = (reqKnown, Just ServerRule {sReqMethod = reqMethod,
                                  sReqUrl = reqUrl,
                                  sReqContents = Map.keys reqKnown})
    | otherwise = (reqKnown, Nothing)
    where (Instruction _ Rule { rMethod =reqMethod, rUrl = reqUrl,
            rContents = reqKnown })= instruction
          validUrl = either (\url -> server url /= "") (/="") reqUrl

accumParseResults:: (Known, [Maybe ServerRule]) -> Instruction ->
  (Known, [Maybe ServerRule])
accumParseResults (known, ruleList) instruction =
    (Map.union newInfo known, newRule:ruleList)
    where (newInfo, newRule) = instructionToRule instruction

parseInstructions:: [Instruction] -> (Known, [ServerRule])
parseInstructions iList = (info, catMaybes rules)
    where (info, rules) = foldl accumParseResults (Map.empty, []) iList

sResponseReceived:: Server -> Response -> Server
sResponseReceived cServer response
    | expected = Server { serverIdentifier = sID, autoGenerated = auto,
                   serverKnowledge = Map.union newInfo sKnown,
                   serverSession = Map.union sessionInfo sSession,
                   serverRules = sRules,
                   pendingSRequests = Map.union sessionRules sPReq,
                   expectedResponses= Map.delete rNonce eSResp,
                   pendingSResponses = spRes, sNonceList= sNL }
    | otherwise = cServer
    where (Server { serverIdentifier = sID, autoGenerated = auto,
            serverKnowledge = sKnown, serverSession = sSession,
            serverRules = sRules, pendingSRequests = sPReq,
            expectedResponses= eSResp, pendingSResponses = spRes,
            sNonceList= sNL }) = cServer
          (Response { resNonce = rNonce,
            instructionList = PageInstructions { autoList = rAList},
            fileList = rFList }) = response
          (oNonce, oReq) = fromMaybe ("", defaultRequest)
            (Map.lookup rNonce eSResp)
          expected = expectedResponse oReq response
          newInfo = filesToShared rFList
          (newSessionInfo, newRules) = parseInstructions rAList
          currentSession = fromMaybe Map.empty $ Map.lookup oNonce sSession
          currentRules = fromMaybe [] $ Map.lookup oNonce sPReq
          sessionInfo =Map.singleton oNonce
            $ Map.union newSessionInfo currentSession
          sessionRules = Map.singleton oNonce $ newRules ++ currentRules

fillInstruction :: Map.Map Domain Known -> Known -> [String] -> Nonce ->
  Instruction -> Maybe Instruction
fillInstruction shared known auto nonce inst
    | Map.null (Map.filter (=="") resultingData) && isJust nUrl =
        Just (Instruction trigger Rule { rType =instTYpe, rMethod =instRMethod,
               rUrl = Left (fromJust nUrl), rContents = resultingData })
    | otherwise = Nothing
    where (Instruction trigger Rule { rType =instTYpe, rMethod =instRMethod,
            rUrl = instUrl, rContents = iContents } )=inst
          nUrl = either Just (\b -> if b==""
                                 then Just emptyUrl
                                 else maybe Nothing (\u -> Just (read u)) (Map.lookup b known) ) instUrl
          incompleteData = Map.keys $ Map.filter (=="") iContents
          knownData = getKnownElems (Just known) incompleteData
          sharedData = getKnownElems (maybe Nothing
            (\a -> Map.lookup (urlDomain a) shared) nUrl ) incompleteData
          genData = genAutoElem nonce auto incompleteData
          resultingData = Map.unions [knownData, sharedData, genData, iContents]

fillComponent :: Map.Map Domain Known -> Known -> [String] -> Nonce ->
  Component -> Maybe Component
fillComponent shared known auto nonce component
    | Nothing `notElem` resInsts = Just Component { cOrigin = cUrl,
        cList = catMaybes resInsts, cPos = pos, cVisible = visible }
    | otherwise = Nothing
    where (Component { cOrigin = cUrl, cList = instList, cPos = pos,
            cVisible = visible }) = component
          resInsts= map (fillInstruction shared known auto nonce) instList

fillComponents :: [Component] -> Map.Map Domain Known -> Known -> [String] ->
  Nonce -> Maybe [Component]
fillComponents [] _ _ _ _ = Just []
fillComponents components shared known auto nonce
    | Nothing `notElem` result = Just $ catMaybes result
    | otherwise = Nothing
    where result= map (fillComponent shared known auto nonce) components

fillInstructions :: PageInstructions -> Map.Map Domain Known -> Known ->
  [String] -> Nonce -> Maybe PageInstructions
fillInstructions instructions shared known auto nonce
    | Nothing `notElem` newAuto && Nothing `notElem` newCond =
        Just PageInstructions { autoList= catMaybes newAuto,
                conditionalList = catMaybes newCond }
    | otherwise = Nothing
    where (PageInstructions { autoList= autoInst,
            conditionalList = condInst })=instructions
          newAuto = map (fillInstruction shared known auto nonce) autoInst
          newCond = map (fillInstruction shared known auto nonce) condInst

fillFile:: Map.Map Domain Known -> Known -> [String] -> Nonce -> Url ->
  WebFile -> Maybe WebFile
fillFile shared known auto nonce url file
    | Map.null (Map.filter (=="") resultingData) =
        Just WebFile { fTtl =ttl, fContent = resultingData }
    | otherwise = Nothing
    where (WebFile { fTtl =ttl, fContent = fData }) = file
          incompleteData = Map.keys $ Map.filter (=="") fData
          knownData = getKnownElems (Just known) incompleteData
          sharedData = getKnownElems (Map.lookup (urlDomain url) shared)
              incompleteData
          genData = genAutoElem nonce auto incompleteData
          resultingData = Map.unions [knownData, sharedData, genData, fData]

fillFiles:: Map.Map Url WebFile -> Map.Map Domain Known -> Known -> [String] ->
  Nonce -> Maybe (Map.Map Url WebFile)
fillFiles fList shared known auto nonce
    | Map.null fList = Just Map.empty
    | all (`elem` Map.keys results) (Map.keys fList)  = Just results
    | otherwise = Nothing
    where results = Map.mapMaybeWithKey (fillFile shared known auto nonce) fList

generateResponse :: Nonce -> Map.Map Domain Known -> Maybe Known ->
  [String] -> Maybe Response -> Maybe Response
generateResponse _ _ Nothing _ _ = Nothing
generateResponse _ _ _ _ Nothing = Nothing
generateResponse nonce sKnown (Just session) auto (Just response)
    | valid = Just Response { destinationIdentifier = newDestID,
                origin = read newOrigin, resNonce = nonce, csp = rCsp,
                componentList = fromJust newComponentList,
                instructionList = fromJust newInstList,
                fileList = fromJust newFileList }
    | otherwise = Just (errorResponse newDestID (read newOrigin) nonce)
    where (Response { destinationIdentifier = dID, origin = dUrl, csp = rCsp,
            componentList = rCList, instructionList = rInstructions,
            fileList = rFileL }) = response
          newDestID = fromMaybe dID $ Map.lookup "dID" session
          newOrigin = fromMaybe (show dUrl) $ Map.lookup "dUrl" session
          newComponentList = fillComponents rCList sKnown session auto nonce
          newInstList = fillInstructions rInstructions sKnown session auto nonce
          newFileList = fillFiles rFileL sKnown session auto nonce
          valid = newDestID /= "" && newOrigin /= "" && isJust newComponentList
                    && isJust newInstList && isJust newFileList

sendResponse:: Server -> Nonce -> (Server, Maybe Response)
sendResponse cServer nonce
    | null pendingReq && not expectedRes =
          let nKnown = Map.lookup nonce sSession
              pRes = Map.lookup nonce spRes
              res = generateResponse nonce sKnown nKnown auto pRes
              nServer = Server { serverIdentifier = sID, autoGenerated= auto,
                serverKnowledge = sKnown,
                serverSession = Map.delete nonce sSession,
                serverRules = sRules,
                pendingSRequests = Map.delete nonce sPReq,
                expectedResponses= eSResp,
                pendingSResponses = Map.delete nonce spRes,
                sNonceList= sNL }
          in (nServer, res)
    | otherwise = (cServer, Nothing)
    where (Server { serverIdentifier = sID, autoGenerated= auto,
            serverKnowledge = sKnown, serverSession = sSession,
            serverRules = sRules, pendingSRequests = sPReq,
            expectedResponses= eSResp, pendingSResponses = spRes,
            sNonceList= sNL }) = cServer
          pendingReq = fromMaybe [] $ Map.lookup nonce sPReq
          expectedRes = Map.fold (\tuple accum -> nonce == fst tuple || accum)
            False eSResp


serverActions :: Server -> [String]
serverActions cServer = results
    where (Server { serverIdentifier = sID, pendingSRequests = sPReq,
            expectedResponses= eSResp, pendingSResponses = spRes,
            serverSession= sSession }) = cServer
          disabledReq = Map.fold (\a accum -> fst a :accum) [] eSResp
          pRequests = map (\a -> sID ++ " Request "++ a) $ filter
            (`notElem` disabledReq) (Map.keys $ Map.filter (\a -> not (null a)) sPReq)
          pResp = filter (`notElem` disabledReq)
            $ Map.keys (Map.filter null sPReq)
          pResponses = map (\k -> let sKnown = fromMaybe Map.empty
                                                      (Map.lookup k sSession)
                                      dID = fromMaybe ""
                                                      (Map.lookup "dID" sKnown)
                                        in sID ++ " -> " ++ dID ++ ": Response "
                                             ++ k)
                         $ Map.keys (Map.filterWithKey
                             (\k _ -> k `elem` pResp) spRes)
          results = pRequests ++ pResponses

serverOptionToEvent :: Server -> String ->
  (Server, Maybe Request, Maybe Response)
serverOptionToEvent cServer option
    | value == "Response" =
        let (nServer, res) = sendResponse cServer (head params)
        in (nServer, Nothing, res)
    | value == "Request" =
        let (nServer, req) = sendRequest cServer (head params)
        in (nServer, req, Nothing)
    | otherwise = (cServer, Nothing, Nothing)
    where (value:params) = drop 3 (words option)
