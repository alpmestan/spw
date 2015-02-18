{-# LANGUAGE OverloadedStrings, TemplateHaskell #-}

module SProxy.Run where

import Config
import DB
import Handlers
import SproxyError

import Control.Monad.Trans
import Data.Default.Class
import Data.Pool
import Network.Wai
import Network.Wai.Handler.Warp hiding (Connection)
import Network.Wai.Middleware.RequestLogger
import Network.Wai.Middleware.Static
import Web.Scotty.Trans
import System.Directory
import System.FilePath
import System.IO

run :: IO Application
run = do
    cfgFile <- fmap (</> ".sproxy-web" <.> "cfg") getHomeDirectory
    config <- getConfig cfgFile
    pool <- createDBPool (dbConnectionString config)
    scottyAppT id id (sproxyWeb (staticDir config) pool)

requestLogger :: MonadIO m => m Middleware
requestLogger = liftIO $ mkRequestLogger def{
        destination = Handle stderr
    }

sproxyWeb :: FilePath -> Pool Connection -> ScottyT SproxyError IO ()
sproxyWeb staticDirectory pool = do
    -- let's log the requests
    middleware =<< requestLogger

    middleware (staticPolicy (hasPrefix "static" >-> addBase staticDirectory))

    -- error page for uncaught exceptions
    defaultHandler handleEx

    get "/"       $ homepage pool

    post "/search" $ searchUserH pool
    post "/delete-user" $ deleteUserH pool
    post "/rename-user" $ renameUserH pool

    -- groups
    get "/groups" $ groupList pool           -- this is the group listing page
    get "/groups.json" $ jsonGroupList pool  -- json endpoint returning an array of group names
    post "/groups" $ jsonUpdateGroup pool    -- endpoint where we POST requests for modifications of groups

    -- group
    get "/group/:group/members" $ memberList pool       -- list of members for a group
    post "/group/:group/members" $ jsonPostMembers pool -- endpoint for POSTing updates to the member list

    -- domains
    get "/domains" $ domainList pool        -- list of domains handled by sproxy
    post "/domains" $ jsonUpdateDomain pool -- endpoint for POSTing updates

    -- privileges for a given domain
    get "/domain/:domain/privileges" $ domainPrivileges pool          -- listing of privileges available on a domain
    get "/domain/:domain/privileges.json" $ jsonDomainPrivileges pool -- json endpoint, array of privilege names
    post "/domain/:domain/privileges" $ jsonPostDomainPrivileges pool -- endpoint for POSTing updates

    -- rules for a given privilege on a given domain
    get "/domain/:domain/privilege/:privilege/rules" $ privilegeRules pool -- listing of paths/methods associated to a privilege
    post "/domain/:domain/privilege/:privilege/rules" $ jsonPostRule pool  -- endpoint for POSTing updates about these

    -- add/remove group privileges
    post "/domain/:domain/group_privileges" $ handleGPs pool -- endpoint for POSTing privilege granting/removal for groups
