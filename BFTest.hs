import           Attacker
import           Browser
import           Criterion.Measurement
import           Data.Either
import           Data.Functor
import           Data.List
import qualified Data.Map              as Map
import           Data.Maybe
import           Data.Ord
--import           Debug.Trace
import           SamlServerFix
import           Server
import           Types
import           User

reqParams:: [Server] -> Url -> Bool
reqParams sList url = any null params
    where srList = Map.filterWithKey (\k _ -> show k == show url) $
                     Map.unions (map serverRules sList)
          partial = concat (Map.elems srList)
          params = map (\(a,_,_)-> a) partial

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

resSent :: Response -> [Server] -> Browser -> ([Server], Browser)
resSent res [] cBrowser
    | rDest == bName = ([], responseReceived cBrowser res)
    | otherwise = ([], cBrowser)
    where rDest = destinationIdentifier res
          bName = browserIdentifier cBrowser
resSent res (x:xs) cBrowser
    | rDest == sName =
        let nServer = sResponseReceived x res
        in (nServer:xs, cBrowser)
    | otherwise =
        let (nSList, nBrowser) = resSent res xs cBrowser
        in (x:nSList, nBrowser)
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
        let val = 4 * lvl
            (_:_:v1:_) = words nAction
            (_:_:v0:_) = words cAction
            nVal = val * if v0 == v1 then 9999 else 1
            (tAttacker, nReq, nRes) = attackerOptionToEvent cAttacker nAction
            (tSList, nBrowser) = maybe (cSList, cBrowser)
                                  (\r -> resSent r cSList cBrowser) nRes
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
            nAttacker = if maybe "" (server . destination) req ==
                             attackerIdentifier cAttacker
                          then
                            maybe cAttacker (`aRequestReceived` cAttacker) req
                          else
                            maybe cAttacker (`interceptedRequest` cAttacker) req
            nState = cState {browser = nBrowser, attacker = nAttacker}
            aVal = if isNothing req
                      then 9999
                      else 10
            nVal = 4 * lvl * (val + aVal)
        in (nVal, (nAction, nState))
    | "U ->" `isPrefixOf` nAction =
        let val = if nAction == cAction then 9999 else 7
            uInput = optionToEvent nAction cUser
            nBrowser = maybe cBrowser (userInputReceived cBrowser) uInput
            nState = cState { browser = nBrowser }
            cVal
                | isAddress' uInput =
                    let url = fromJust (getAddress' uInput)
                    in if reqParams cSList url
                          then 65
                          else 9999
                | isBack' uInput || isForward' uInput = 40
                | otherwise = 10
            nVal = 4 * (if lvl == 0 then 1 else lvl) * (val + cVal)
        in (nVal, (nAction, nState))
    | otherwise =
        let val = lvl * 4
            (nSList, nReq, nRes) = serverListToEvent cSList nAction
            tAttacker = maybe cAttacker (`interceptedRequest` cAttacker) nReq
            pAttacker = maybe tAttacker (`interceptedResponse` tAttacker) nRes
            nAttacker = getInfoFromServerList pAttacker nSList
            nState = cState { servers = nSList, attacker = nAttacker }
        in (val, (nAction, nState))
    where (State { user = cUser, browser = cBrowser, servers = cSList,
            attacker = cAttacker }) = cState

eval:: State -> (State, Bool)
eval cState =
    (cState { mGoals = nMGoals, aGoals = nAGoals}, null nMGoals)
    where cAttacker = attacker cState
          aID = attackerIdentifier cAttacker
          reqQ = requestQueue cAttacker
          resQ = responseQueue cAttacker
          (reqGoals, resGoals) = partitionEithers (mGoals cState)
          (attReq, pReq) = partition (\r -> originIdentifier r == aID ) reqGoals
          (aReq, nReq) = partition (`elem` reqQ) pReq
          (aRes, nRes) = partition (`elem` resQ) resGoals
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
          tStates = filter ((3000 >) . fst) sStates
          oStates = map snd tStates

loop:: State -> IO()
loop cState =
    let (flag, res) = loop' 0 cState "Start" (False, [])
    in if flag
          then putStrLn $ unlines res
          else putStrLn "No attack found :("

main:: IO ()
main = do
    putStrLn "Welcome"
    loop iState
    secs <$> getCPUTime >>= print
    putStrLn ""
    putStrLn "Bye!"
    where url1 = Url { server = "rp", path = "one" }
          url2 = Url { server = "idp", path = "one" }
          kUrls = [url1,url2]
          gKnown = Map.singleton "idp" (show url2)
          uKnown = Map.fromList [("id", "userid"), ("user", "uname"),
                     ("pass", "pass")]
          uDKnown = Map.fromList [("rp", uKnown), ("idp", uKnown)]
          myUser = initUser "user" gKnown uDKnown kUrls
          myBrowser = initEmptyBrowser "browser"
          (myServers, goals) = getServers
          aKnown = Map.fromList [("rp", "rp2")]
          myAttacker = initAttacker "attacker" False ["rp"] [] [] []
                         Map.empty aKnown
          iState = State myUser myBrowser myServers myAttacker goals []
