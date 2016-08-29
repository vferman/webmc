import           BFTest
import           Browser
import           Criterion.Measurement
import           Data.Functor
import           Data.Map              as Map
import           OauthOneVuln
import           Types
import           User


main:: IO ()
main = do
    putStrLn "Welcome"
    loop iState
    secs <$> getCPUTime >>= print
    putStrLn ""
    putStrLn "Bye!"
    -- OauthOne Specs
    where url1 = Url { server = "client", path = "one" }
          url2 = Url { server = "resource", path = "initiate" }
          kUrls = [url1,url2]
          gKnown = Map.singleton "resource_url" (show url2)
          uKnown = Map.fromList [("user", "uname"), ("pass", "pass")]
          uDKnown = Map.fromList [("client", uKnown), ("resource", uKnown)]
          myUser = initUser "user" gKnown uDKnown kUrls
          myBrowser = initEmptyBrowser "browser"
          (myServers, goals, myAttacker) = getServers
          iState = State myUser myBrowser myServers myAttacker goals []
