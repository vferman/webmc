import           Browser
import           Data.Char
import qualified Data.Map    as Map
import Data.Maybe
import           Attacker
--import           Debug.Trace
import WebKereberos
import           Server
import           Types
import           User

printActions:: Attacker -> User -> Browser -> [Server] -> IO ()
printActions _ _ _ [] = putStrLn "Error"
printActions cAttacker cUser cBrowser sList = do
    putStrLn "The following are the available actions:"
    putStr toPrint
    where attActions = attackerActions cAttacker
          userActions = getUserActions cUser (generateDisplay cBrowser)
          bActions = getBrowserActions cBrowser
          sActions = foldl (\accum cServer -> accum ++ getServerActions cServer) [] sList
          resultingActions = attActions ++ userActions ++ bActions ++ sActions
          tempActions = zipWith (\n action -> show n ++ " - " ++ action)
                          ([1..]::[Integer]) resultingActions
          attTitle = "Attacker Actions:":take (length attActions) tempActions
          userTitle = "User Actions:": take (length userActions)
                        (drop (length attActions) tempActions)
          browserTitle = "Browser Actions:": take (length bActions)
                           (drop (length attActions + length userActions)
                             tempActions)
          serverTitle = "Server Actions:":drop (length attActions +
                          length userActions + length bActions) tempActions

          defaultActions = ["Syustem Actions:",
            "R - Return to a previous State", "S - Print system status"]
          toPrint = unlines $ defaultActions ++ attTitle ++ userTitle ++
                                browserTitle ++ serverTitle

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
    | option <= lAActions = do
        putStrLn (show option ++ "performing Attacker action")
        putStrLn $ attActions !! (option - 1)
        let (pAttacker, nReq, nRes) = attackerOptionToEvent cAttacker
                                        (attActions !! (option - 1))
            (tSList, nBrowser, tAttacker) = maybe (sList, cBrowser, pAttacker)
                                              (\r -> resSent r sList cBrowser pAttacker)
                                                nRes
            nSList
                | isJust nReq = map (reqToServer (fromJust nReq)) tSList
                | otherwise = tSList
            nAttacker = getInfoFromServerList tAttacker nSList
        loop cUser nBrowser nSList nAttacker
    | (option - lAActions ) <= lUActions  = do
        putStrLn (show option ++ " performing user action")
        putStrLn $ uActions !! (option - lAActions - 1)
        let uInput = optionToEvent (uActions !! (option - lAActions - 1)) cUser
            nBrowser = maybe cBrowser (userInputReceived cBrowser) uInput
        loop cUser nBrowser sList cAttacker
    | (option - lAActions - lUActions) <= lBActions = do
        putStrLn (show option ++ " performing browser action")
        let bOption = option - lAActions - lUActions - 1
            (tempBrowser, req) = browserOptionToEvent cBrowser
                                (bActions !! bOption)
            nBrowser = maybe cBrowser (requestSent tempBrowser) req
            --nSList = maybe sList (\reqValue -> map (reqToServer reqValue) sList)
            --           req
            tAttacker = maybe cAttacker (`interceptedRequest` cAttacker) req
            nAttacker = getInfoFromServerList tAttacker sList
            --nAInfo = neededInfo nAttacker
            --aSuccess = foldl (\accum attack -> if length attack <= 1
            --                                       then "Attack successful"
            --                                       else accum) "" nAInfo
        putStrLn $ bActions !! bOption
        putStrLn ""
        print (files nBrowser)
        print req
        --mapM_ print nAInfo
        --putStrLn aSuccess
        putStrLn ""
        loop cUser nBrowser sList nAttacker
    | (option -lAActions - lUActions - lBActions) <= lSActions = do
        putStrLn (show option ++ " performing server action")
        let sOption = option - lAActions - lUActions - lBActions -1
            (nSList, req, res) = serverListToEvent sList sOption
            -- reqSList = maybe tempSList (\reqVal ->
            --              map (reqToServer reqVal) tempSList) req
            -- (nSList, nBrowser, tAttacker) = maybe
            --                                   (reqSList, cBrowser, cAttacker)
            --                                   (\rVal -> resSent rVal reqSList
            --                                               cBrowser cAttacker)
            --                                   res
            rqAttacker = maybe cAttacker (`interceptedRequest` cAttacker) req
            tAttacker = maybe rqAttacker (`interceptedResponse` cAttacker) res
            nAttacker = getInfoFromServerList tAttacker sList
            --nAInfo = neededInfo nAttacker
            --aSuccess = foldl (\accum attack -> if length attack <= 1
            --                                      then "Attack successful"
            --                                      else accum) "" nAInfo
        putStrLn $ sActions !! sOption
        putStrLn ""
        --mapM_ print nAInfo
        --putStrLn aSuccess
        putStrLn ""
        loop cUser cBrowser nSList nAttacker
    | otherwise = putStrLn "Error Please input a valid option, number too large"
    where attActions = attackerActions cAttacker
          uActions = getUserActions cUser (generateDisplay cBrowser)
          bActions = getBrowserActions cBrowser
          sActions = foldl (\accum cServer -> accum ++ getServerActions cServer) [] sList
          lAActions = length attActions
          lUActions = length uActions
          lBActions = length bActions
          lSActions = length sActions

loop:: User -> Browser -> [Server] -> Attacker-> IO ()
loop cUser cBrowser sList cAttacker= do
    printActions cAttacker cUser cBrowser sList
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
    where url1 = Url { server = "was", path = "one" }
          url2 = Url { server = "att", path =""}
          kUrls = [url1, url2]
          gKnown = Map.empty
          uKnown = Map.fromList [("user", "uname"), ("pass", "pass")]
          uDKnown = Map.singleton "kdc" uKnown
          myUser = initUser "user" gKnown uDKnown kUrls
          myBrowser = initEmptyBrowser "browser"
          (myServers, _, myAttacker) = getServers
