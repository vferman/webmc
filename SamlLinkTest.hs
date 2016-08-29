import           BFTest
import           Browser
import           Criterion.Measurement
import           Data.Functor
import           Data.Map              as Map
import           SamlLink
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
          url2 = Url { server = "att", path = "" }
          kUrls = [url1,url2]
          myUser = initUser "user" Map.empty Map.empty kUrls
          myBrowser = initEmptyBrowser "browser"
          (myServers, goals, myAttacker) = getServers
          iState = State myUser myBrowser myServers myAttacker goals []
