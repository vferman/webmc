import           Attacker
import           Browser
import           Criterion.Measurement
import           Data.Char
import           Data.Functor
import           Data.List
import qualified Data.Map              as Map
--import           Debug.Trace
import           Planner
import           SamlServer
import           Server
import           Types
import           User



reqToServer :: Request -> Server -> Server
reqToServer req cServer
    | rDest == sName = requestReceived cServer req
    | otherwise = cServer
    where rDest = server (destination req)
          sName = serverIdentifier cServer

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

attackerStatus:: Attacker -> Bool
attackerStatus cAttacker
    | any (\i -> length i <= 1) cAInfo = True
    | otherwise = False
    where cAInfo = neededInfo cAttacker


executeAction:: Int -> Int -> User -> Browser -> [Server] -> Attacker ->
  (Bool, [String]) -> String -> (Bool, [String])
executeAction maxLevl cLevel cUser cBrowser sList cAttacker (flag, aList) option
    | flag = (flag, aList)
    | "U ->" `isPrefixOf` option = do
        let uInput = optionToEvent option cUser
            nBrowser = maybe cBrowser (userInputReceived cBrowser) uInput
            attack = attackerStatus cAttacker
        if attack
            then (attack, [option])
            else
                let (rFlag, rAList) = loop' maxLevl cLevel cUser nBrowser sList cAttacker (flag , aList)
                in if rFlag
                    then (rFlag, option:rAList)
                    else (rFlag, rAList)

    | "B ->" `isPrefixOf` option = do
        let (tempBrowser, req) = browserOptionToEvent cBrowser option
            nBrowser = maybe cBrowser (requestSent tempBrowser) req
            nSList = maybe sList (\reqValue -> map (reqToServer reqValue) sList)
                       req
            nAttacker = getInfoFromServerList cAttacker nSList
            attack = attackerStatus nAttacker
        if attack
            then (attack, [option])
            else
                let (rFlag, rAList) = loop' maxLevl cLevel cUser nBrowser nSList nAttacker (flag , aList)
                in if rFlag
                    then (rFlag, option:rAList)
                    else (rFlag, rAList)
    | otherwise = do
        let (tempSList, req, res) = serverListToEvent sList option
            reqSList = maybe tempSList (\reqVal ->
                     map (reqToServer reqVal) tempSList) req
            (nSList, nBrowser) = maybe (reqSList, cBrowser)
                               (\rVal -> resSent rVal reqSList cBrowser) res
            nAttacker = getInfoFromServerList cAttacker nSList
            attack = attackerStatus cAttacker
        if attack
            then (attack, [option])
            else
                let (rFlag, rAList) = loop' maxLevl cLevel cUser nBrowser nSList nAttacker (flag , aList)
                in if rFlag
                    then (rFlag, option:rAList)
                    else (rFlag, rAList)



loop':: Int -> Int -> User -> Browser -> [Server] -> Attacker ->
  (Bool, [String]) -> (Bool, [String])
loop' maxLevel cLevel cUser cBrowser sList cAttacker (flag, aList)
    | flag = (flag, aList)
    | maxLevel == cLevel = (flag, init aList)
    | otherwise = foldl' (executeAction maxLevel (cLevel + 1) cUser cBrowser sList cAttacker) (flag,aList) actList
    where uActions = getUserActions cUser (generateDisplay cBrowser)
          bActions = getBrowserActions cBrowser
          sActions = foldl (\accum cServer -> accum ++ getServerActions cServer) [] sList
          actList = uActions ++ bActions ++ sActions

ploop':: Int -> User -> Browser -> [Server] -> Attacker -> IO ()
ploop' maxLevel cUser cBrowser sList cAttacker
    |maxLevel <= 11 = do
        let (flag, aList) = loop' maxLevel 0 cUser cBrowser sList cAttacker
                                (False, [])
        if flag
            then do
                putStrLn "The attack trace is the following"
                putStr $ unlines aList
            else putStrLn "No attack found :("
    | otherwise = do
        let (flag, aList) = foldl' (\accum val -> loop' val 0 cUser cBrowser
                                                sList cAttacker accum)
                                    (False, []) [12 .. maxLevel]
        if flag
            then do
                putStrLn "The attack trace is the following"
                putStr $ unlines aList
            else putStrLn "No attack found :("

loop:: User -> Browser -> [Server] -> Attacker-> IO ()
loop cUser cBrowser sList cAttacker= do
    putStrLn "What would you like to be the maximun recursion level?"
    level <- getLine
    putStrLn ""
    if all isDigit level
        then do
            let maxLevel = read level
            secs <$> time_ (ploop' maxLevel cUser cBrowser sList cAttacker) >>= print

        else do
            putStrLn "Please enter a valid number"
            loop cUser cBrowser sList cAttacker


main:: IO ()
main = do
    putStrLn "Welcome"
    loop myUser myBrowser myServers myAttacker
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
          (myServers, aGoal) = getServers
          myAttacker = initAttacker "attacker" ["rp"] aGoal [] Map.empty
