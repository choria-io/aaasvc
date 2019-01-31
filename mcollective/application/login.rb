module MCollective
  class Application
    class Login < Application
      description "Choria Orchestrator AAA Login"

      usage <<-USAGE
  mco login

  You will be prompted for a username and password that should
  be known to your configured Authentication service.

  For more information please visit:

     https://github.com/choria-io/aaasvc
  USAGE

      exclude_argument_sections "common", "filter", "rpc"

      def config
        Config.instance
      end

      def choria
        @_choria ||= Util::Choria.new(false)
      end

      def login_request(user, pass)
        {
          "username" => user,
          "password" => pass
        }
      end

      def login_url
        url = config.pluginconf["choria.aaasvc.login.url"]
        raise("Please configure a login URL") if [nil, ""].include?(url)

        URI.parse(url)
      end

      def fetch_token(user, pass)
        uri = login_url

        post = choria.http_post(uri.request_uri)
        post.body = login_request(user, pass).to_json
        post["Content-type"] = "application/json"

        http = choria.https(:target => uri.host, :port => uri.port)
        http.use_ssl = false if uri.scheme == "http"
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl?

        resp = http.request(post)

        login = {}

        if resp.code == "200"
          login = JSON.parse(resp.body)
        else
          raise("Could not login: %s: %s" % [resp.code, resp.body])
        end

        raise(login["error"]) if login["error"]

        raise("no token received") unless login["token"]

        login["token"]
      end

      def ask_user
        default_user = ENV["USER"]

        if default_user
          print "Username (%s): " % default_user
        else
          print "Username: " % default_user
        end
        username = STDIN.gets.chomp
        username = default_user if username == ""

        username
      end

      def ask_password
        require "io/console"

        print "Password: "
        STDIN.noecho(&:gets).chomp
      end

      def token_env
        config.pluginconf["choria.security.request_signer.token_environment"]
      end

      def token_file
        file = config.pluginconf["choria.security.request_signer.token_file"]
        return nil unless file

        File.expand_path(file)
      end

      def save_token(token)
        raise("No token provided") unless token
        raise("No token provider") if token == ""

        if token_env
          raise("Do not know how to start a shell with your token, please set SHELL environment") unless ENV["SHELL"]
          puts("Starting a new shell with %s set, please exit when done" % token_env)

          ENV[token_env] = token
          exec(ENV["SHELL"])
        elsif token_file
          File.unlink(token_file) if File.exist?(token_file)

          File.open(token_file, File::CREAT|File::TRUNC|File::RDWR, 0600) do |file|
            file.print(token)
          end

          puts("Token saved to %s" % token_file)
        else
          raise("No token environment or file have been configured")
        end
      end

      def main
        username = ask_user
        password = ask_password

        abort("Please enter a username") if username == ""
        abort("Please enter a password") if password == ""

        puts

        save_token(fetch_token(username, password))
      end
    end
  end