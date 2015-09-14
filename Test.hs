import           Browser
import           Data.Char
import qualified Data.Map    as Map
import           Data.Maybe
--import           OIDServer
import           Attacker
import           Debug.Trace
import           Planner
import           SamlServer
import           Server
import           Types
import           User

printActions:: User -> Browser -> [Server] -> IO ()
printActions _ _ [] = putStrLn "Error"
printActions cUser cBrowser sList = do
    putStrLn "The following are the available actions:"
    putStr toPrint
    where userActions = getUserActions cUser (generateDisplay cBrowser)
          bActions = getBrowserActions cBrowser
          sActions = foldl (\accum cServer -> accum ++ getServerActions cServer) [] sList
          resultingActions = userActions ++ bActions ++ sActions
          tempActions = zipWith (\n action -> show n ++ " - " ++ action) [1..] resultingActions
          serverTitle = "Server Actions:":drop (length userActions +
                          length bActions) tempActions
          browserTitle = "Browser Actions:": take (length bActions)
                           (drop (length userActions) tempActions)
          userTitle = "User Actions:": take (length userActions) tempActions
          defaultActions = ["Syustem Actions:",
            "R - Return to a previous State", "S - Print system status"]
          toPrint = unlines $ defaultActions ++ userTitle ++ browserTitle ++
            serverTitle

printStatus:: Browser -> [Server] -> IO ()
printStatus cBrowser sList = do
    putStrLn ""
    putStr res
    putStrLn ""
    where bStatus = getBrowserStatus cBrowser
          sStatus = foldl (\a s -> a ++ serverStatus s) [] sList
          res = unlines (bStatus ++ sStatus)

reqToServer :: Request -> Server -> Server
reqToServer req cServer
    | rDest == sName = requestReceived cServer req
    | otherwise = cServer
    where rDest = server (destination req)
          sName = serverIdentifier cServer

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

serverListToEvent :: [Server] -> Int ->
  ([Server], Maybe Request, Maybe Response)
serverListToEvent [] _ = ([], Nothing, Nothing)
serverListToEvent (x:xs) option
    | option < lSActions =
        let (nServer, req, res) = serverOptionToEvent x (sActions !! option)
        in (nServer:xs, req, res)
    | otherwise =
        let (nSList, req, res) = serverListToEvent xs (option - lSActions)
        in (x:nSList, req, res)
    where sActions = serverActions x
          lSActions = length sActions

executeOption :: User -> Browser -> [Server] -> Attacker -> Int -> IO ()
executeOption cUser cBrowser sList cAttacker option
    | option <= lUActions  = do
        putStrLn (show option ++ " performing user action")
        putStrLn $ uActions !! (option - 1)
        let uInput = optionToEvent (uActions !! (option - 1)) cUser
            nBrowser = maybe cBrowser (userInputReceived cBrowser) uInput
        loop cUser nBrowser sList cAttacker
    | (option - lUActions) <= lBActions = do
        putStrLn (show option ++ " performing browser action")
        let bOption = option - lUActions - 1
            (tempBrowser, req) = browserOptionToEvent cBrowser
                                (bActions !! bOption)
            nBrowser = maybe cBrowser (requestSent tempBrowser) req
            nSList = maybe sList (\reqValue -> map (reqToServer reqValue) sList)
                       req
            nAttacker = getInfoFromServerList cAttacker nSList
            nAInfo = neededInfo nAttacker
            aSuccess = foldl (\accum attack -> if length attack <= 1
                                                   then "Attack successful"
                                                   else accum) "" nAInfo
        putStrLn $ bActions !! bOption
        putStrLn ""
        mapM_ print nAInfo
        putStrLn aSuccess
        putStrLn ""
        loop cUser nBrowser nSList nAttacker
    | (option - lUActions - lBActions) <= lSActions = do
        putStrLn (show option ++ " performing server action")
        let sOption = option - lUActions - lBActions -1
            (tempSList, req, res) = serverListToEvent sList sOption
            reqSList = maybe tempSList (\reqVal ->
                         map (reqToServer reqVal) tempSList) req
            (nSList, nBrowser) = maybe (reqSList, cBrowser)
                                   (\rVal -> resSent rVal reqSList cBrowser) res
            nAttacker = getInfoFromServerList cAttacker nSList
            nAInfo = neededInfo nAttacker
            aSuccess = foldl (\accum attack -> if length attack <= 1
                                                  then "Attack successful"
                                                  else accum) "" nAInfo
        putStrLn $ sActions !! sOption
        putStrLn ""
        mapM_ print nAInfo
        putStrLn aSuccess
        putStrLn ""
        loop cUser nBrowser nSList nAttacker
    | otherwise = putStrLn "Error Please input a valid option, number too large"
    where uActions = getUserActions cUser (generateDisplay cBrowser)
          bActions = getBrowserActions cBrowser
          sActions = foldl (\accum cServer -> accum ++ getServerActions cServer) [] sList
          lUActions = length uActions
          lBActions = length bActions
          lSActions = length sActions

loop:: User -> Browser -> [Server] -> Attacker-> IO ()
loop cUser cBrowser sList cAttacker= do
    printActions cUser cBrowser sList
    putStrLn "What would you like to do?"
    option <- getLine
    if not (null option)
        then if option == "R"
            then do
                putStrLn "returning to a prevous state"
                putStrLn ""
                return ()
            else if option == "S"
                then do putStrLn "Printing System Status"
                        printStatus cBrowser sList
                        loop cUser cBrowser sList cAttacker
                else if all isDigit option
                    then do executeOption cUser cBrowser sList cAttacker
                              (read option)
                            loop cUser cBrowser sList cAttacker
                    else do putStrLn "Please input a valid option"
                            loop cUser cBrowser sList cAttacker
        else do putStrLn "Please input a valid option"
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
