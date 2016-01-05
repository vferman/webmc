{-
Project: WebMC: a model checker for the web
Author: Victor Ferman
File: Attacker.hs
Description: This file defines a generic Attacker's actions an capabilities,
    used in order to know what the attacker needs in order to achieve a
    successful attack on a protocol
-}

module Attacker where

import           Browser
import qualified Data.List  as List
import qualified Data.Map   as Map
import           Data.Maybe
import           Types


initAttacker :: String -> Bool -> [String] -> [String] -> [Server] ->
  [String] -> Map.Map Url WebFile -> Known -> Attacker
initAttacker aID sstart fcSID scSID sList autoGen aFiles aKnown =
    Attacker { attackerIdentifier = aID, asSessions = sstart,
      fCorruptIDs = fcSID, sCorruptIDs = scSID, expectedByServer = sEMsgs,
      acquiredKeys = aKeys, generated = autoGen,
      acquiredInfo = Map.empty, acquiredFiles = aFiles,
      attackerKnowledge = aKnown, requestQueue = [], responseQueue = [],
      eResponses= Map.empty, aNonceList = [1..] }
    where sEMsgs = Map.unions $ map expectedFromServer sList
          cSList = filter (\srvr -> serverIdentifier srvr `elem` fcSID) sList
          aKeys = List.nub $ concatMap knownKeys cSList


expectedFromServer :: Server -> Map.Map Url [[String]]
expectedFromServer cServer = result
    where rules = serverRules cServer
          result = Map.map (map (\(a,_,_)-> a)) rules


getInfoFromServer :: Attacker -> Server -> Attacker
getInfoFromServer cAttacker servr
    | serverIdentifier servr `elem` fcSID =
          cAttacker {acquiredKeys = kList,
           acquiredInfo = Map.union browserInfo aInfo }
    | otherwise = cAttacker
    where (Attacker { fCorruptIDs = fcSID, acquiredKeys = aKeys,
            acquiredInfo = aInfo }) = cAttacker
          sessions = serverSession servr
          kList = List.nub $ aKeys ++ knownKeys servr
          browserInfo = Map.foldWithKey
            (\_ value accum -> Map.union
              (maybe Map.empty (`Map.singleton` value) (Map.lookup "dID" value))
              accum) Map.empty sessions


getInfoFromServerList :: Attacker -> [Server] -> Attacker
getInfoFromServerList = foldl getInfoFromServer


incompleteData :: [String] -> [String] -> [String] -> Known -> [String]
incompleteData needed auto known info = results
    where iKeys = Map.keys info
          notInAuto = filter (`notElem` auto) needed
          notInKnown = filter (`notElem` known) notInAuto
          results = filter (`notElem` iKeys) notInKnown


interceptedRequest :: Request -> Attacker -> Attacker
interceptedRequest cReq cAttacker =
    cAttacker{ acquiredInfo = nInfo, requestQueue = cReq:reqQ }
    where (Attacker { fCorruptIDs = fcSID, acquiredInfo = aInfo,
            requestQueue = reqQ }) = cAttacker
          nInfo = if server (destination cReq) `elem` fcSID
                    then Map.insert (originIdentifier cReq) (payload cReq) aInfo
                    else aInfo


interceptedResponse :: Response -> Attacker -> Attacker
interceptedResponse cRes cAttacker =
    cAttacker { responseQueue = cRes:resQ }
    where (Attacker { responseQueue = resQ }) = cAttacker


aRequestReceived :: Request -> Attacker -> Attacker
aRequestReceived cReq cAttacker =
    cAttacker { acquiredInfo = Map.union nKnown aKnown }
    where (Request { originIdentifier = oID, payload =rKnown }) = cReq
          aKnown = acquiredInfo cAttacker
          nKnown = Map.singleton oID rKnown


knowledgeFromComponent :: [Component] -> Map.Map Domain Known
knowledgeFromComponent [] = Map.empty
knowledgeFromComponent ccList =
    foldl (\accum comp -> Map.union (knowLedgeFromInstruction
                                        (server (cOrigin comp))
                                        (cList comp)) accum) Map.empty ccList

knowLedgeFromInstruction :: Domain -> [Instruction] -> Map.Map Domain Known
knowLedgeFromInstruction _ [] = Map.empty
knowLedgeFromInstruction domain ciList =
    foldl (\accum inst -> let (Instruction _ cRule) = inst
                          in Map.union (Map.singleton domain (rContents cRule))
                                          accum) Map.empty ciList

extractKnowledge :: Domain -> [Component] -> [Instruction] ->
  Map.Map Domain Known
extractKnowledge cDomain ccList ciList =
    Map.union (knowledgeFromComponent ccList)
                 (knowLedgeFromInstruction cDomain ciList)

aResponseReceived :: Response -> Attacker -> Attacker
aResponseReceived cRes cAttacker
    | aID == dID && isJust expected =
        let (PageInstructions { autoList = rAList,
               conditionalList =rCIList }) = riList
            nKnown = extractKnowledge (server rOrigin) rcList
                         (rAList ++ rCIList)
        in cAttacker { acquiredInfo = Map.union nKnown aInfo,
             acquiredFiles = Map.union rfList aFiles,
             eResponses = Map.delete rNonce aERes }
    | otherwise = cAttacker
    where (Attacker { attackerIdentifier = aID, acquiredInfo = aInfo,
            acquiredFiles = aFiles, eResponses = aERes }) = cAttacker
          (Response { destinationIdentifier = dID, origin = rOrigin,
            resNonce = rNonce, componentList = rcList, instructionList = riList,
            fileList = rfList }) = cRes
          expected = Map.lookup rNonce aERes

reqToAction :: Request -> [String]
reqToAction cReq =
    ["Attacker Pass Request: "++ oID ++"-> " ++ server dID]
    where (Request { originIdentifier = oID , destination = dID }) = cReq

resToAction :: Attacker -> Response -> [String]
resToAction cAttacker cRes =
    ["Attacker Pass Response: " ++ server rOrigin ++ " -> "++ dID] ++
      cInstructions ++ cCookies
    where (Attacker {fCorruptIDs = corruptSID, sCorruptIDs = sCorruptSID,
            acquiredFiles = aFiles }) = cAttacker
          (Response { destinationIdentifier = dID, origin = rOrigin }) = cRes
          cInstructions = ["Attacker add Instructions: " ++ server rOrigin ++ " -> " ++
                             dID | server rOrigin `elem` corruptSID ||
                                      server rOrigin `elem` sCorruptSID ]
          cCookies = ["Attacker add Cookies: "++ show x ++ " to " ++ server rOrigin ++
                        " -> " ++ dID |
                        x <- List.subsequences (Map.keys aFiles),
                        (server rOrigin `elem` corruptSID ||
                          server rOrigin `elem`sCorruptSID) &&
                          not (Map.null aFiles)]

fillableMsgs :: Attacker -> Url -> [[String]] -> [String]
fillableMsgs cAttacker = fillableMsgs' aID known
    where (Attacker {attackerIdentifier = aID, generated = autoGen,
            acquiredFiles = aFiles, attackerKnowledge = aKnown }) = cAttacker
          cookies = concatMap (Map.keys . fContent) (Map.elems aFiles)
          known = autoGen ++ cookies ++ Map.keys aKnown

fillableMsgs' :: String -> [String] -> Url -> [[String]] -> [String]
fillableMsgs' pID known dest paramLists =
    let prev = map (\l -> if null l || all (`elem` known ) l
                            then "Attacker Send "++ show l ++ " to " ++ show dest ++
                                    " with " ++ pID
                            else "") paramLists
    in filter (not . null) prev

sessionActions :: Attacker -> [String]
sessionActions cAttacker
    | sstart = aMsgs ++ oMsgs
    | otherwise = []
    where (Attacker {asSessions = sstart, fCorruptIDs = fcSID,
            expectedByServer = sEMsgs, acquiredInfo = aInfo }) = cAttacker
          pMsgs = Map.filterWithKey (\k _ -> server k `notElem` fcSID) sEMsgs
          aMsgs = Map.foldWithKey (\k v a -> a ++ fillableMsgs cAttacker k v) []
                    pMsgs
          poMsgs = Map.map (foldl (\accum v -> if null v
                                                  then accum
                                                  else v:accum) [[]])  pMsgs
          oMsgs = Map.foldWithKey (\pID known a ->
                    Map.foldWithKey (\url req acc -> acc ++
                                      fillableMsgs' pID (Map.keys known) url
                                        req) a poMsgs)
                    [] aInfo

attackerActions :: Attacker -> [String]
attackerActions cAttacker = result
    where (Attacker { asSessions = sstart, requestQueue = reqQ,
            responseQueue = resQ }) = cAttacker
          actReq = if null reqQ then [] else reqToAction (head reqQ)
          actRes = if null resQ then [] else resToAction cAttacker (head resQ)
          actAtt = if not sstart then [] else sessionActions cAttacker
          result = actReq ++ actRes ++ actAtt

addCookies :: Attacker -> Response -> [String] -> Response
addCookies cAttacker cRes sUrls
    | cROrig `elem` cIDs =
        cRes { fileList = Map.unionWith
                            (\nf cf-> let ac = fContent nf
                                          cc = fContent cf
                                          nc = Map.union ac cc
                                      in WebFile (fTtl nf) nc )
                            nCookies cCookies }
    | otherwise = cRes
    where cIDs = fCorruptIDs cAttacker ++ sCorruptIDs cAttacker
          cROrig= server (origin cRes)
          urls = map read sUrls
          cookies = acquiredFiles cAttacker
          nCookies = Map.filterWithKey (\k _ -> k `elem` urls) cookies
          cCookies = fileList cRes


fillInst :: String -> Known -> [String] -> Int -> Url -> [[String]] -> [Instruction]
fillInst pID known auto nonce dUrl paramLists =
    mapMaybe (\pl -> let pCont = pPayload pl
                         miss = missing pCont pl
                         rCont = rPayload miss pCont
                           in if all (`elem` Map.keys rCont) pl
                                then Just (Instruction trig (rl rCont))
                                else Nothing) $ filter (not . null) paramLists
    where  trig = Right True
           rl p = Rule { rType = RuleType Normal Full, rMethod = Post,
           rUrl = Left dUrl, rContents = p }
           pPayload p = Map.filterWithKey (\k _ -> k `elem` p) known
           missing p= filter (\f -> f `notElem` Map.keys p &&
                                     f `elem` auto)
           rPayload m p= if null m
                        then p
                        else Map.union p
                              (generateValues pID nonce m)

hiddenFromComp :: Component -> Maybe Component
hiddenFromComp cComp
    | not (null ncIList) = Just (cComp { cList = ncIList, cVisible = False })
    | otherwise = Nothing
    where (Component { cList = cIList })= cComp
          ncIList = filter (\(Instruction _ r) -> "?" `elem`
                               Map.elems (rContents r) ) cIList

addInstructions :: Attacker -> Response -> Attacker
addInstructions cAttacker cRes
    | cROrig `elem` scIDs =
        let aInst = Map.foldWithKey
                      (\k v a -> a ++ fillInst aID fKnown auto (head aNL) k v)
                      [] pInst
            aURL = Url aID ""
            nRule = Rule (RuleType Normal Full) Post (Left aURL) rKnow
            nInst = Instruction (Right True) nRule
            nComp = mapMaybe hiddenFromComp cRCList
            nRes = cRes { componentList = nComp++cRCList,
                          instructionList = PageInstructions{ autoList = nInst:
                            (aInst ++ aInst), conditionalList = cInstL }}
        in cAttacker {responseQueue = nRes:tail resQ, aNonceList = drop 1 aNL}
    | cROrig `elem` fcSID =
        let aInst = Map.foldWithKey
                      (\k v a -> a ++ fillInst aID aKnow auto (head aNL) k v)
                      [] pInst
            nRes = cRes {instructionList = PageInstructions{ autoList = aInstL++
                          aInst, conditionalList = cInstL }}
        in cAttacker {responseQueue = nRes:tail resQ, aNonceList = drop 1 aNL}
    | otherwise = cAttacker
    where (Attacker { attackerIdentifier = aID, fCorruptIDs = fcSID,
            sCorruptIDs = scIDs, expectedByServer = cEBS, generated = auto,
            acquiredInfo = aInfo, acquiredFiles = aFiles, responseQueue = resQ,
            aNonceList = aNL }) = cAttacker
          (Response { destinationIdentifier = cRDest, origin = rOrig, componentList = cRCList, instructionList = resInst,
            fileList = cRCookies }) = cRes
          cROrig = server rOrig
          aInstL = autoList resInst
          cInstL = conditionalList resInst
          cKnown = fromMaybe Map.empty (Map.lookup cRDest aInfo)
          cookies = Map.unions $ map fContent (Map.elems aFiles)
          aKnow =  Map.union cookies cKnown
          prKnow = Map.unions $ Map.elems (extractKnowledge cROrig cRCList
                                           (aInstL ++ cInstL))
          rcKnow = Map.unions $ map fContent (Map.elems cRCookies)
          rKnow = Map.union rcKnow prKnow
          fKnown = Map.union rKnow aKnow
          pInst = Map.filterWithKey (\k _ -> server k `notElem` fcSID) cEBS

generateValues :: String -> Int -> [String] -> Known
generateValues pID nonce fields = Map.fromList result
    where values = map (\v -> pID ++ v ++show nonce ) fields
          result = zip fields values

newRuleReq :: String -> Url -> [String] -> Known -> [String] -> [Int] ->
  (Maybe Rule, Maybe Request)
newRuleReq aID url params known auto aNL
    | all (`elem` Map.keys rPayload) params = (Just nRule, Just nReq)
    | otherwise = (Nothing, Nothing)
    where pPayload = Map.filterWithKey (\k _ -> k `elem` params) known
          missing = filter (\f -> f `notElem` Map.keys pPayload &&
                                    f `elem` auto) params
          rPayload = if null missing
                        then pPayload
                        else Map.union pPayload
                               (generateValues aID (head aNL) missing)
          nRule = Rule (RuleType Normal Full) Post (Left url) rPayload
          nReq = ruleToRequest nRule aID ("nonce" ++ aID ++ show(head aNL))

reqWithData :: Attacker -> [String] -> Url -> String ->
  (Attacker, Maybe Request)
reqWithData cAttacker params url pID
    | isJust rule && isJust nReq =
        let rNonce = "nonce" ++ aID ++ show (head aNL)
            eRule = fromJust rule
            cERes = eResponses cAttacker
            nAttacker = cAttacker {eResponses = Map.insert rNonce eRule cERes,
                          aNonceList = drop 1 aNL }
        in (nAttacker, nReq)
    | otherwise = (cAttacker, Nothing)
    where rules = expectedByServer cAttacker
          aNL = aNonceList cAttacker
          autoGen = generated cAttacker
          toReq = Map.filterWithKey (\k v -> k == url && params `elem` v ) rules
          aID = attackerIdentifier cAttacker
          rInfo = if pID == aID
                    then attackerKnowledge cAttacker
                    else fromMaybe Map.empty (Map.lookup pID
                                                (acquiredInfo cAttacker))
          (rule, nReq) = if Map.null toReq
                            then (Nothing, Nothing)
                            else newRuleReq aID url params rInfo autoGen aNL


attackerOptionToEvent :: Attacker -> String ->
  (Attacker, Maybe Request, Maybe Response)
attackerOptionToEvent cAttacker option
    | val1 == "Pass" && val2 == "Request:" && not (null reqQ) =
        (cAttacker {requestQueue = tail reqQ } , Just (head reqQ), Nothing)
    | val1 == "Pass" && val2 == "Response:" && not (null resQ) =
        (cAttacker {responseQueue = tail resQ } , Nothing, Just (head resQ))
    | val1 == "Add" && val2 == "Cookies:" && not (null resQ) =
        let cUrls =read $ unwords (takeWhile (/="to") params)
            nRes = addCookies cAttacker (head resQ) cUrls
        in (cAttacker {responseQueue = nRes:tail resQ } , Nothing, Nothing )
    | val1 == "Add" && val2 == "Instructions:"  && not (null resQ) =
        let nAttacker = addInstructions cAttacker (head resQ)
        in (nAttacker, Nothing, Nothing)
    | val1 == "Send" && sessions =
        let (rParamL, rest) = span (/="to") (val2:params)
            rParams = read $ unwords rParamL
            (urlL, pIDL) = span (/="with") rest
            reqUrl = read $ unwords (drop 1 urlL)
            rPID = unwords (drop 1 pIDL)
            (nAttacker, nReq) = reqWithData cAttacker rParams reqUrl rPID
        in (nAttacker, nReq, Nothing)
    | otherwise = (cAttacker, Nothing, Nothing)
    where (_:val1:val2:params) = words option
          (Attacker {asSessions = sessions , requestQueue = reqQ,
            responseQueue = resQ}) = cAttacker

neededInfo :: Attacker -> [Request] -> [Request]
neededInfo attackr aGoal =
    List.nub . map fst . filter (\(_, s) -> null s ) $ results
    where (Attacker { generated = autoGen, acquiredInfo = info,
            attackerKnowledge = aKnown })= attackr
          aKFields = Map.keys aKnown
          iList = Map.elems info
          iData = map (\req -> (req, incompleteData (Map.keys (payload req))
            autoGen aKFields)) aGoal
          results = concatMap (\k -> map (\(r, f)-> (r, f k)) iData) iList
