import           BFTest
import           Browser
import           Criterion.Measurement
import           Data.Functor
import           Data.Map              as Map
import           WebKereberos
import           Types
import           User


main:: IO ()
main = do
    putStrLn "Welcome"
    (pFlag, pState) <- loopState iState
    if pFlag
       then do
            putStrLn ""
            putStrLn "Continuing with second goal"
            loop (secondGoal pState)
       else putStrLn ":("
    secs <$> getCPUTime >>= print
    putStrLn ""
    putStrLn "Bye!"
    where url1 = Url { server = "was", path = "one" }
          aUrl = Url { server = "att", path = "" }
          kUrls = [aUrl, url1]
          myUser = initUser "user" Map.empty Map.empty kUrls
          myBrowser = initEmptyBrowser "browser"
          (myServers, goals, myAttacker) = getServers
          iState = State myUser myBrowser myServers myAttacker goals []
