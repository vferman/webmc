module BFTest where

import           Attacker
import           Browser
import           Data.Either
import           Data.List
import qualified Data.Map    as Map
import           Data.Maybe
import           Data.Ord
--import           Debug.Trace
import           Server
import           Types
import           User

reqParams:: [Server] -> Url -> Bool
reqParams sList url = any null params
    where srList = Map.filterWithKey (\k _ -> show k == show url) $
                     Map.unions (map serverRules sList)
          partial = concat (Map.elems srList)
          params = map (\(a,_,_,_)-> a) partial

serverListToEvent :: [Server] -> String ->
  ([Server], Maybe Request, Maybe Response)
serverListToEvent [] _ = ([], Nothing, Nothing)
serverListToEvent (x:xs) option
    | serverIdentifier x `isPrefixOf` option =
        let (nServer, req, res) = serverOptionToEvent x option
        in (nServer:xs, req, res)
    | otherwise =
        let (nSList, req, res) = serverListToEvent xs option
        in (x:nSList, req, res)

resSent :: Response -> [Server] -> Browser -> Attacker ->
  ([Server], Browser, Attacker)
resSent res [] cBrowser attackr
    | rDest == bName = ([], responseReceived cBrowser res, attackr)
    | rDest == "attacker" = ([], cBrowser, aResponseReceived res attackr)
    | otherwise = ([], cBrowser, attackr)
    where rDest = destinationIdentifier res
          bName = browserIdentifier cBrowser
resSent res (x:xs) cBrowser attackr
    | rDest == sName =
        let nServer = sResponseReceived x res
        in (nServer:xs, cBrowser, attackr)
    | otherwise =
        let (nSList, nBrowser, nAttackr) = resSent res xs cBrowser attackr
        in (x:nSList, nBrowser, nAttackr)
    where rDest = destinationIdentifier res
          sName = serverIdentifier x

reqToServer :: Request -> Server -> Server
reqToServer req cServer
    | rDest == sName = requestReceived cServer req
    | otherwise = cServer
    where rDest = server (destination req)
          sName = serverIdentifier cServer

executeAction :: State -> Int-> String -> String -> (Int, (String, State))
executeAction cState lvl cAction nAction
    | "Attacker" `isPrefixOf` nAction =
        let val = if cAction == nAction then 99999 else 2 * lvl
            (a:_:v1:_) = words nAction
            (b:_:v0:_) = if cAction == "Start"
                            then ["", "", "Start", ""]
                            else words cAction
            nVal = val * ((if v0 == v1 then 99999 else 1) +
                           (if a == b then 10 else 0))
            (pAttacker, nReq, nRes) = attackerOptionToEvent cAttacker nAction
            (tSList, nBrowser, tAttacker) = maybe (cSList, cBrowser, pAttacker)
                                  (\r -> resSent r cSList cBrowser pAttacker)
                                    nRes
            nSList
                | isJust nReq = map (reqToServer (fromJust nReq)) tSList
                | otherwise = tSList
            nAttacker = getInfoFromServerList tAttacker nSList
            nState = cState { browser = nBrowser, servers = nSList,
                       attacker = nAttacker}
        in (nVal, (nAction, nState))
    | "B ->" `isPrefixOf`nAction =
        let val = 2
            (tempBrowser, req) = browserOptionToEvent cBrowser nAction
            nBrowser = maybe cBrowser (requestSent tempBrowser) req
            tAttacker = if maybe "" (server . destination) req ==
                             attackerIdentifier cAttacker
                          then
                            maybe cAttacker (`aRequestReceived` cAttacker) req
                          else
                            maybe cAttacker (`interceptedRequest` cAttacker) req
            nAttacker = getInfoFromServerList tAttacker cSList
            nState = cState {browser = nBrowser, attacker = nAttacker}
            aVal = if isNothing req
                      then 99999
                      else 10
            nVal = 2 * lvl * (val + aVal)
        in (nVal, (nAction, nState))
    | "U ->" `isPrefixOf` nAction =
        let val = if nAction == cAction then 99999 else 7
            uInput = optionToEvent nAction cUser
            nBrowser = maybe cBrowser (userInputReceived cBrowser) uInput
            nState = cState { browser = nBrowser }
            cVal
                | isAddress' uInput =
                    let url = fromJust (getAddress' uInput)
                    in if reqParams cSList url
                          then 65
                          else 99999
                | isBack' uInput || isForward' uInput = 40
                | otherwise = 10
            nVal = 2 * (if lvl == 0 then 1 else lvl) * (val + cVal)
        in (nVal, (nAction, nState))
    | otherwise =
        let val = if cAction == nAction then 99999 else 2 * lvl
            (nSList, nReq, nRes) = serverListToEvent cSList nAction
            tAttacker = maybe cAttacker (`interceptedRequest` cAttacker) nReq
            pAttacker = maybe tAttacker (`interceptedResponse` tAttacker) nRes
            nAttacker = getInfoFromServerList pAttacker nSList
            nState = cState { servers = nSList, attacker = nAttacker }
        in (val, (nAction, nState))
    where (State { user = cUser, browser = cBrowser, servers = cSList,
            attacker = cAttacker }) = cState

cmpReq::[String] -> Request -> Request -> Bool
cmpReq [] myRes other = myRes == other
cmpReq aList myReq other
    | all (`elem` oPlKeys) mPlKeys =
        let comparableK = filter (`notElem` aList) mPlKeys
            mVals = Map.filterWithKey (\k _ -> k `elem` comparableK)
                      (payload myReq)
            oVals =  Map.filterWithKey (\k _ -> k `elem` comparableK)
                      (payload other)
        in mVals == oVals
    | otherwise = False
    where mPlKeys = Map.keys $ payload myReq
          oPlKeys = Map.keys $ payload other

cmpInst:: [String] -> [Instruction] -> Instruction -> Bool
cmpInst _ [] _ = False
cmpInst aList (x:iList) goal
    |mTrig == oTrig && oRType == mRType && oRMethod == mRMethod &&
       oRUrl == mRUrl && all (`elem` Map.keys oRContent) (Map.keys mRContent) =
        let mVals = Map.filterWithKey (\k _ -> k `notElem` aList) mRContent
            oVals = Map.filterWithKey (\k _ -> k `elem` Map.keys mVals)
                      oRContent
        in mVals == oVals || cmpInst aList iList goal
    |otherwise = cmpInst aList iList goal
    where (Instruction oTrig oRule) = x
          (Instruction mTrig mRule) = goal
          oRType = rType oRule
          mRType = rType mRule
          oRMethod = rMethod oRule
          mRMethod = rMethod mRule
          oRUrl = rUrl oRule
          mRUrl = rUrl mRule
          oRContent = rContents oRule
          mRContent = rContents mRule

cmpInstList::[String] -> [Instruction] -> [Instruction] -> Bool
cmpInstList aList oIList = all (cmpInst aList oIList)

cmpFile::[String] -> WebFile -> WebFile -> Bool
cmpFile aList oFile mFile = mContent == oContent
    where mContent = Map.filterWithKey (\k _ -> k `notElem` aList)
                       (fContent mFile)
          oContent = Map.filterWithKey (\k _ -> k `elem` Map.keys mContent)
                       (fContent oFile)

cmpFileList::[String] -> Map.Map (Either String Url) WebFile ->
  Map.Map (Either String Url) WebFile -> Bool
cmpFileList aList mFList oFList =
    and $ Map.foldlWithKey
      (\a k v -> (maybe False (\m -> cmpFile aList m v) (Map.lookup k oFList) :
                  a ))
      [] mFList

cmpComp:: [String] -> [Component] -> Component -> Bool
cmpComp _ [] _ = False
cmpComp aList (x:rCList) comp
    | mOrig == oOrig && mVis == oVis && mPos == oPos =
        let res = cmpInstList aList (cList x) (cList comp)
        in res || cmpComp aList rCList comp
    | otherwise = cmpComp aList rCList comp
    where oOrig = cOrigin x
          mOrig = cOrigin comp
          oVis = cVisible x
          mVis = cVisible comp
          oPos = cPos x
          mPos = cPos comp

cmpCompList:: [String] -> [Component] -> [Component] -> Bool
cmpCompList aList mCList oCList = all (cmpComp aList oCList) mCList

reqInList:: [Server] -> Request -> [Request] -> Bool
reqInList _ _ [] = False
reqInList sList req (x:rList) = val || reqInList sList req rList
    where aList = concatMap autoGenerated sList
          val = cmpReq aList req x

cmpRes::[String] -> Response -> Response -> Bool
cmpRes aList goal other
    | mDID == oDID && mOrig == oOrig =
        let mCompList = componentList goal
            oCompList = componentList other
            (PageInstructions {autoList = mAIList,
              conditionalList = mCIList}) = instructionList goal
            mIList = mAIList ++ mCIList
            (PageInstructions {autoList = oAIList,
              conditionalList = oCIList}) = instructionList other
            oIList = oAIList ++ oCIList
            mFList = fileList goal
            oFList =  fileList other
            c1 = cmpCompList aList mCompList oCompList
            c2 = cmpInstList aList mIList oIList
            c3 = cmpFileList aList mFList oFList
            in mDID == oDID && mOrig == oOrig && c1 && c2 && c3
    | otherwise = False
    where mDID = destinationIdentifier goal
          oDID = destinationIdentifier other
          mOrig = origin goal
          oOrig = origin other

resInList:: [Server] -> Response -> [Response] -> Bool
resInList _ _ [] = False
resInList sList goal queue = any (cmpRes aList goal) queue
    where aList = concatMap autoGenerated sList

eval:: State -> (State, Bool)
eval cState =
    (cState { mGoals = nMGoals, aGoals = nAGoals}, null nMGoals)
    where cAttacker = attacker cState
          sList = servers cState
          aID = attackerIdentifier cAttacker
          reqQ = requestQueue cAttacker
          resQ = responseQueue cAttacker
          (reqGoals, resGoals) = partitionEithers (mGoals cState)
          (attReq, pReq) = partition (\r -> originIdentifier r == aID ) reqGoals
          (aReq, nReq) = partition (\r -> reqInList sList r reqQ) pReq
          (aRes, nRes) = partition (\r -> resInList sList r resQ) resGoals
        --   (aReq, nReq) = partition (`elem` reqQ) pReq
        --   (aRes, nRes) = partition (`elem` resQ) resGoals
          attAGoals = neededInfo cAttacker attReq
          nAttMGoals = filter (`notElem` attAGoals) attReq
          nAGoals = map Left (aReq ++ attAGoals) ++ map Right aRes
          nMGoals = map Left (nReq ++ nAttMGoals) ++ map Right nRes

loop':: Int -> State -> String -> (Bool, [String])-> (Bool, [String])
loop' cLevel cState cAction (cFlag, accum)
    | cFlag  = (cFlag, accum)
    | eValue = (eValue, [cAction])
    | otherwise = foldl
                    (\(nFlag, accm) (action, state) ->
                        let (aFlag, aList) = loop' (cLevel+1) state action
                                               (nFlag, accm)
                        in if aFlag
                              then (aFlag, action:aList)
                              else (aFlag, aList))
                    (False, []) oStates
    where (nCState, eValue) = eval cState
          (State { user = cUser, browser = cBrowser, servers = cSList,
            attacker = cAttacker }) = nCState
          uActions = getUserActions cUser (generateDisplay cBrowser)
          bActions = getBrowserActions cBrowser
          sActions = concatMap getServerActions cSList
          aActions = attackerActions cAttacker
          pActions = uActions ++ bActions ++ sActions ++ aActions
          pStates = map (executeAction nCState cLevel cAction) pActions
          sStates = sortBy (comparing fst) pStates
          tStates = filter ((4000 >) . fst) sStates
          oStates = map snd tStates

loopState':: Int -> State -> String -> (Bool, [String], State) ->
  (Bool, [String], State)
loopState' cLevel cState cAction (cFlag, accum, fState)
    | cFlag  = (cFlag, accum, fState)
    | eValue = (eValue, [cAction], cState)
    | otherwise = foldl
                    (\(nFlag, accm, tState) (action, state) ->
                        let (aFlag, aList, nState) = loopState' (cLevel+1) state
                              action (nFlag, accm, tState)
                        in if aFlag
                              then (aFlag, action:aList, nState)
                              else (aFlag, aList, tState))
                    (False, [], fState) oStates
    where (nCState, eValue) = eval cState
          (State { user = cUser, browser = cBrowser, servers = cSList,
            attacker = cAttacker }) = nCState
          uActions = getUserActions cUser (generateDisplay cBrowser)
          bActions = getBrowserActions cBrowser
          sActions = concatMap getServerActions cSList
          aActions = attackerActions cAttacker
          pActions = uActions ++ bActions ++ sActions ++ aActions
          pStates = map (executeAction nCState cLevel cAction) pActions
          sStates = sortBy (comparing fst) pStates
          tStates = filter ((4000 >) . fst) sStates
          oStates = map snd tStates

loopState:: State -> IO(Bool, State)
loopState cState =
    let (flag, res, nState) = loopState' 0 cState "Start" (False, [], cState)
    in do
        if flag
          then putStrLn $ unlines res
          else putStrLn "No Attack Found"
        return (flag, nState)

loop:: State -> IO()
loop cState =
    let (flag, res) = loop' 0 cState "Start" (False, [])
    in if flag
          then putStrLn $ unlines res
          else putStrLn "No attack found :("
