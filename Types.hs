{-
Project: WebMC: a model checker for the web
Author: Victor Ferman
File: Types.hs
Description: This file defines all of the data types for our model checker, it
    includes principals, urls, knowledge, messages.

-}

module Types where

--import System.Random
import qualified Data.Map as Map

{-
    The definitions are constructive and as such, we will start by defining the
    basic blocks of the system and work from there to create more complex data
    definitions that are required
-}

-- Definition for encryption keys (public, private and shared)
data Key = Pub String | Pri String | Shr String String
             deriving (Show, Eq, Read)

--Definition od an encryption type, accepts anything
data Enc a = Enc a Key | Sig a Key deriving (Show, Eq, Read)

-- Domains, may refer to a server or a family of servers
type Domain = String

--Nonces, either fresh or reused
type Nonce = String


--URLs used to distinguish servers and actions on those servers
data Url = Url { server :: Domain
               , path :: String
               } deriving(Show, Read, Eq, Ord)

emptyUrl :: Url
emptyUrl = Url { server = "", path ="" }


{-
    We start by defining what the user can do and what it receives,
    useful since the user knows little about the internal workings
    of all other participants and just sees snapshots of the current
    state of the system
-}

--output from the Browser to the User
--Used by the user to know what her options are to interact with the world
data Display = Display { lock :: Bool -- SSL/TLS lock
                       , location :: Url -- Address bar
                       , visibleLinks :: [Int] -- Links in the web page
                       , visibleForms :: Map.Map Int [String] -- like previous
                       , back:: Bool -- Enabled/disabled Back button
                       , forward:: Bool -- Enabled/disabled Forward button
                       } deriving(Show, Eq)

-- a position in the display used to represent clicks
type Pos = Int

-- shorthand for a map that represents knowledge
type Known = Map.Map String String

-- data to be sent to the browser by the user
-- used to represent form submition
data FormInput = FormInput Known Pos deriving(Show, Eq)

-- Different kinds of user inputs, represents the possible actions of a user
data UserInput = Address Url | Position Pos | Form FormInput | Back | Forward
     deriving(Show, Eq)


isAddress:: UserInput -> Bool
isAddress (Address _) = True
isAddress _ = False

isBack:: UserInput -> Bool
isBack Back = True
isBack _ = False

isForward:: UserInput -> Bool
isForward Forward = True
isForward _ = False

getAddress:: UserInput -> Maybe Url
getAddress (Address url) = Just url
getAddress _ = Nothing

isAddress':: Maybe UserInput -> Bool
isAddress' (Just (Address _)) = True
isAddress' _ = False

isBack':: Maybe UserInput -> Bool
isBack' (Just Back) = True
isBack' _ = False

isForward':: Maybe UserInput -> Bool
isForward' (Just Forward) = True
isForward' _ = False

getAddress':: Maybe UserInput -> Maybe Url
getAddress' (Just (Address url)) = Just url
getAddress' _ = Nothing


{-
    After defining what the user interacts with we continue with the browser
    the browser is the most complicated principal and is the one that moves
    forward everything
-}

-- useful to diferentiate how a message will be created
data RequestType = Normal | Scripted deriving(Show, Eq, Ord)

-- useful to know what information is being requested
data ContentType = Full | Script | Frame | Resource deriving(Show, Eq, Ord)

-- combaining how and what is requested into a single chunk
data RuleType = RuleType RequestType ContentType deriving(Show, Eq, Ord)

-- represents the method/encodign the browser will use to send a message
data RequestMethod = Get | Post | Put | Delete deriving(Show, Eq, Ord)


-- represents whether an action is available or not
type Trigger = Either Pos Bool;

-- represents what is to be done by the browser at some future time
data Rule = Rule { rType :: RuleType
                 , rMethod :: RequestMethod
                 , rUrl :: Either Url String
                 , rContents :: Known
                 } deriving(Show, Eq, Ord)

-- Like the previous but moddified to work on the server
data ServerRule = ServerRule { sReqMethod :: RequestMethod
                             , sReqUrl :: Either Url String
                             , sReqContents :: [String]
                             } deriving(Show, Eq, Ord)

-- represents Intructions to eventually be executed by the browser
data Instruction = Instruction Trigger Rule deriving (Show, Eq, Ord)

-- Things the browser has loaded and the user may interact with
data Component = Component { cOrigin :: Url --origin of the data
                           , cList :: [Instruction] -- links, etc
                           , cPos :: Pos -- where in the screen it is
                           , cVisible :: Bool -- Wheter is Visible on Invisible
                           } deriving(Show, Eq, Ord)

-- Content Security Policies, the browser uses these in order to decide whether
-- the a request for certain content type can be made to some URL
data Csp = Csp { scriptList :: [Domain]
               , frameList :: [Domain]
               , resourceList :: [Domain]
               } deriving(Show, Eq, Ord)

-- Lists of instructions received when first requesting a web page
data PageInstructions = PageInstructions { autoList :: [Instruction]
                                         , conditionalList :: [Instruction]
                                         } deriving(Show, Eq, Ord)

-- Web page, with all of the information in contains
data WebPage = WebPage { wOrigin :: Url -- Where the web page comes from
                       , wCsp :: Csp -- Content Security Policy from the Server
                       , wElem :: [Component] -- Components loaded
                       , wInstructions :: PageInstructions -- Scripts
                       } deriving(Show, Eq)


-- Used to represent cookies and other information storage options
data WebFile = WebFile { fTtl :: Int -- Time To Live (Not Used Yet)
                       , fContent :: Known -- Cookie Contents
                       } deriving(Show, Eq, Ord)

-- Used to represent history in browsers
data Visited = Visited { previous :: [Maybe WebPage]
                       , next :: [Maybe WebPage]
                       } deriving(Show, Eq)

-- A response is what a Browser receives from a server, it may contain:
data Response = Response { destinationIdentifier :: String --Request origin
                         , origin :: Url -- Where the request was made to
                         , resNonce :: Nonce -- Nonce from the original request
                         , csp :: Csp -- CSP for the server or page if any
                         , componentList :: [Component] -- Payload
                         , instructionList :: PageInstructions -- Scripts
                         , fileList :: Map.Map (Either String Url)  WebFile
                           -- Cookies
                         } deriving(Show, Eq, Ord)

-- A request is the output from a browser to a server, it contains
data Request = Request { originIdentifier :: String -- Who makes the request
                       , destination :: Url -- Where the request is going
                       , reqNonce :: Nonce -- nonce to keep track
                       , method :: RequestMethod -- Mehtod for the server
                       , payload :: Known -- information included in the request
                       } deriving(Show, Eq, Ord)

-- empty request
defaultRequest :: Request
defaultRequest = Request { originIdentifier = "",
                   destination = Url { server = "", path = ""}, reqNonce = "",
                   method = Get, payload = Map.empty }


{-
    section used to define the characteristics of the different principals
-}

-- what the user knows about some web pages
type UserKnowledge = Map.Map Domain Known

-- data structure used to represent the user and her knowledge
data User = User { userIdentifier :: String -- Identifier (useful if we have several users)
                 , generalKnowledge :: Known -- known information to be used by any web page
                 , domainKnowledge :: UserKnowledge -- known information about an specific web page
                 , knownUrls :: [Url] -- known urls
                 } deriving(Show, Eq)

-- data structure that represents the browser and its state
data Browser = Browser { browserIdentifier :: String -- Broser name (like in user)
                       , visitedPages :: Visited -- Browser's history
                       , files :: Map.Map (Either String Url) WebFile -- cookies
                       , current :: Maybe WebPage -- what's being presented to the user
                       , original :: Maybe WebPage -- what's being cached
                       , pendingResponses :: [(Nonce, Rule)] -- expected responses
                       , pendingRequest :: [Rule] -- Request queue
                       , bNonceList :: [Int]
                       } deriving(Eq)

instance Show Browser where
    show Browser { browserIdentifier = bID, visitedPages = bVisited,
      files = bFiles, current = bCW, original = bOW, pendingResponses = bPR,
      pendingRequest = bPReq, bNonceList = bNL}
      =
      "Browser { browserIdentifier = " ++ bID ++ " visitedPages = " ++
        show bVisited ++ " files = " ++ show bFiles ++ " current = " ++ show bCW
        ++ " original = " ++ show bOW ++ " pendingResponses = " ++ show bPR ++
        " pendingRequest = " ++ show bPReq ++ " bNonceList = [" ++ show
        (head bNL) ++ "...] }"


--Data structure that represents a server and its state
data Server = Server { serverIdentifier :: String
                     , autoGenerated :: [String] -- generated info
                     {- what will be stored in persistent sessions and what is
                          the session identifier-}
                     , persistentData ::  (String, [String])
                     , keyDesc :: [String] -- names of fields that contain keys
                     , trackingDesc :: [String] -- fields that should be tracked
                     , knownKeys :: [Key] -- all keys a server knows
                     , knownData :: Map.Map String [String] -- verifiable info
                     {- what the server knows about other servers-}
                     , serverKnowledge :: Map.Map Domain Known
                     {- transient sessions with all the data gathered in order
                         to create a response -}
                     , serverSession :: Map.Map Nonce Known
                     {- information storage, depends on the definition of
                         persistentData -}
                     , persistentSession :: Map.Map (String, String) Known
                     {- Tracked values that have been seen -}
                     , seen :: Map.Map String [String]
                     {- what the server must do when receiving requests -}
                     , serverRules :: Map.Map Url [([String], [ServerRule],
                          Response, Maybe Response)]
                     {- triggered requests -}
                     , pendingSRequests :: Map.Map Nonce [ServerRule]
                     {- information expected after a request was made -}
                     , expectedResponses :: Map.Map Nonce (Nonce, Request)
                     {- responses waiting for data in order to be sent -}
                     , pendingSResponses :: Map.Map Nonce Response
                     , sNonceList :: [Int]
                     } deriving(Eq)

instance Show Server where
    show Server { serverIdentifier = sID, autoGenerated = autoGen,
           persistentData = pData, keyDesc = kDesc, trackingDesc = tDesc,
           knownKeys = kKeys, knownData = kData, serverKnowledge = sKnown,
           serverSession = sSession, persistentSession = pSession, seen = vSeen,
           serverRules = sRules, pendingSRequests = pReqs,
           expectedResponses = eRes, pendingSResponses = pRes,
           sNonceList = sNL }
      =
      "Server { serverIdentifier = "++ sID ++ "\nautoGenerated = " ++
      show autoGen ++ "\npersistentDataDescription = " ++ show pData ++
      "\nfieldsWithKeys = "++ show kDesc ++ "\ntrackedFields = "++ show tDesc ++
      "\nknownKeys = " ++ show kKeys ++ "\nknownData = " ++show kData ++
      "\nserverKnowledge = " ++ show sKnown ++ "\nServerSession = " ++
      show sSession ++ "\npersistentSessions = " ++ show pSession ++
      "\nseenValues = " ++ show vSeen ++ "\nserverRules =" ++ show sRules ++
      "\nPendingSRequests = " ++ show pReqs ++ "\nexpectedResponses = " ++
      show eRes ++"\npendingSResponses =" ++ show pRes ++
      "\n sNonceList = [" ++show (head sNL) ++ "...] }"


--data structure that represents the attacker and its state
data Attacker = Attacker { attackerIdentifier :: String -- attacker's name
                         , asSessions :: Bool -- will it have its own sessions?
                         , fCorruptIDs :: [String] -- servers fully corrupted
                         , sCorruptIDs :: [String] -- servers that the attacker corrupted but not fully, the attacker may acceess the messages but cannot directly access the data
                         , expectedByServer :: Map.Map Url [[String]]
                         , acquiredKeys :: [Key] -- compromised keys
                         , generated :: [String] -- data generated by the attacker
                         , acquiredInfo :: Map.Map String Known --information about a server or browser that was obtained by the attacker
                         , acquiredFiles :: Map.Map (Either String Url) WebFile -- cookies
                         , attackerKnowledge :: Known -- information the attacker knows by default
                         , requestQueue :: [Request] --Network queue
                         , responseQueue :: [Response] -- Network queue
                         , eResponses :: Map.Map Nonce Rule --Expected responses
                         , aNonceList :: [Int]
                         } deriving(Eq)

instance Show Attacker where
    show Attacker { attackerIdentifier = aID, asSessions = sFlag,
           fCorruptIDs = fCsIDs, sCorruptIDs = sCsIDs, acquiredKeys = aKeys,
           generated = autoGen, acquiredInfo = aInfo, acquiredFiles = aFiles,
           attackerKnowledge = aKnown, requestQueue = reqQ,
           responseQueue = resQ, eResponses = eRes, aNonceList =aNL}
      =
      "Attacker { attackerIdentifier = "++ aID ++ "\nownsSessions = " ++
      show sFlag ++ "\nfullyCorupted = " ++ show fCsIDs ++
      "\npartiallyCcorrupted" ++ show sCsIDs ++ "\nacquiredKeys = " ++
      show aKeys ++ "\nautoGenerated = " ++ show autoGen ++
      "\nacquiredInfo = " ++ show aInfo ++ " \nacquiredFiles = " ++
      show aFiles  ++ "\nattackerKnowledge = "  ++  show aKnown ++
      "\nrequestQueue = " ++ show reqQ ++ "\nresponseQueue = " ++ show resQ ++
      "\nexpectedResponses = " ++ show eRes ++ "aNonceList = [" ++
      show (head aNL) ++ "...] }"


-- state of the system
data State = State { user :: User
                   , browser :: Browser
                   , servers :: [Server]
                   , attacker :: Attacker
                   , mGoals :: [Either Request Response] -- a request we expect the attacker to generate so we can say it was successful
                   , aGoals :: [Either Request Response]
                   } deriving(Show, Eq)

stringToPos:: String -> Pos
stringToPos str = read str::Pos
