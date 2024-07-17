import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.util.Objects;



public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception{


   //  System.setProperty("https.proxyHost", "127.0.0.1");
  //   System.setProperty("https.proxyPort", "8081");
//
        Parent root = FXMLLoader.load(Objects.requireNonNull(getClass().getClassLoader().getResource("fds.fxml")));
        primaryStage.setTitle("geoserver CVE-2024-36401 一键漏洞利用工具 By:MingKer");
        primaryStage.setScene(new Scene(root, 700, 750));
        primaryStage.show();
       // primaryStage.setMaximized(true);
      //  primaryStage.setResizable(false);



    }
    public static void main(String[] args) {
        launch(args);
    }
}
