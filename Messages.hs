{-
Project: WebMC: a model checker for the web
Author: Victor Ferman
File: Messages.hs
Description: This file defines operations on messages, like equality,
    compatibility and concatenation.

-}

module Messages (concatRequest,
                 concatResponse,
                 compatible )where

import Types
import qualified Data.Map as Map


{-
    concatRequest and concatResponse are helper functions used to concatenate
    messages, there is not a general function since there is no point in
    concatenating other types of messages (i.e. displays and inputs)
-}
concatRequest::Request -> Request -> Request
concatRequest req1 req2 =
    (Request {originIdentifier = oi, destination = dest, reqNonce = nonce,
      method = m, payload = Map.union pl1 pl2 })
    where (Request { originIdentifier = oi, destination = dest, reqNonce = nonce,
            method = m, payload = pl1}) = req1
          (Request { originIdentifier = _, destination = _, reqNonce = _,
            method = _, payload = pl2 }) = req2

concatResponse::Response -> Response -> Response
concatResponse res1 res2 =
    (Response { destinationIdentifier = dest, origin = o, resNonce = n,
      csp = (Csp { scriptList = scl1 ++ scl2, frameList = frml1 ++ frml2,
      resourceList = rscl1 ++ rscl2 }), componentList = cl1 ++ cl2,
      instructionList = (PageInstructions {autoList = al1 ++ al2,
      conditionalList = cil1 ++ cil2}), fileList = Map.union fl1 fl2 })
    where (Response {destinationIdentifier = dest, origin = o, resNonce = n,
            csp = (Csp { scriptList = scl1, frameList = frml1,
            resourceList = rscl1}), componentList = cl1,
            instructionList = ( PageInstructions {autoList = al1,
            conditionalList = cil1 }), fileList = fl1}) = res1
          (Response { destinationIdentifier = _, origin = _, resNonce = _,
            csp = (Csp { scriptList = scl2, frameList = frml2,
            resourceList = rscl2 }), componentList = cl2,
            instructionList = ( PageInstructions { autoList = al2,
            conditionalList = cil2 }), fileList = fl2 }) = res2


{-
    not exported helper function to decide wheter the payloads of two requests are compatible
-}
compatibleContents:: [(String,String)] -> [(String,String)] -> Bool
compatibleContents [] _ = True
compatibleContents intended received
    | (length intended <= length received) && elem x received =
        compatibleContents xs received
    | otherwise = False
    where (x:xs) = intended

{-
    Function used to check for "compatibility" the notion that a request will
    be accepted by a server if it contains at least the required fields and will
    most likely ignore the remaining extra data
-}
compatible:: Request -> Request -> Bool
compatible req1 req2
    | oi1 == oi2 && dest == dest2 && m1 == m2 =
        compatibleContents (Map.toList pl1) (Map.toList pl2)
    | otherwise = False
    where (Request { originIdentifier = oi1, destination = dest, reqNonce = _,
            method = m1, payload = pl1 }) = req1
          (Request {originIdentifier = oi2, destination = dest2, reqNonce = _,
            method = m2, payload = pl2 }) = req2
