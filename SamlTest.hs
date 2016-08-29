import           BFTest
import           Browser
import           Criterion.Measurement
import           Data.Functor
import           Data.Map              as Map
import           SamlServer
import           Types
import           User


main:: IO ()
main = do
    putStrLn "Welcome"
    loop iState
    secs <$> getCPUTime >>= print
    putStrLn ""
    putStrLn "Bye!"
    --saml specs
    where url1 = Url { server = "rp", path = "one" }
          url2 = Url { server = "idp", path = "one" }
          kUrls = [url1,url2]
          gKnown = Map.singleton "idp" (show url2)
          uKnown = Map.fromList [("id", "userid"), ("user", "uname"),
                     ("pass", "pass")]
          uDKnown = Map.fromList [("rp", uKnown), ("idp", uKnown)]
          myUser = initUser "user" gKnown uDKnown kUrls
          myBrowser = initEmptyBrowser "browser"
          (myServers, goals, myAttacker) = getServers
          iState = State myUser myBrowser myServers myAttacker goals []
