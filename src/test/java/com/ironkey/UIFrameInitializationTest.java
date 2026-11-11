package com.ironkey;

import com.ironkey.ui.DashboardFrame;
import com.ironkey.ui.LoginFrame;
import com.ironkey.ui.RegisterFrame;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.awt.GraphicsEnvironment;

import static org.junit.jupiter.api.Assertions.*;

class UIFrameInitializationTest {

    @Test
    @DisplayName("Swing Frames should initialize components without throwing exceptions")
    void testFrameInitialization() {
        if (GraphicsEnvironment.isHeadless()) {
            System.out.println("Running in headless environment, skipping desktop GUI display test.");
            return;
        }

        assertDoesNotThrow(() -> {
            LoginFrame loginFrame = new LoginFrame();
            assertNotNull(loginFrame.getTitle());
            loginFrame.dispose();
        }, "LoginFrame should construct cleanly");

        assertDoesNotThrow(() -> {
            RegisterFrame registerFrame = new RegisterFrame();
            assertNotNull(registerFrame.getTitle());
            registerFrame.dispose();
        }, "RegisterFrame should construct cleanly");

        assertDoesNotThrow(() -> {
            com.ironkey.model.User testUser = new com.ironkey.model.User("tester", "test@domain.com", "hash", "salt1", "salt2");
            testUser.setUserId(1L);
            javax.crypto.SecretKey key = com.ironkey.security.KeyDerivationService.deriveVaultKey(
                    "Pass#12345678".toCharArray(), com.ironkey.security.KeyDerivationService.generateKeyDerivationSalt());
            com.ironkey.util.SessionManager.getInstance().startSession(testUser, key);

            DashboardFrame dashboardFrame = new DashboardFrame();
            assertNotNull(dashboardFrame.getTitle());
            dashboardFrame.dispose();

            com.ironkey.util.SessionManager.getInstance().clearSession();
        }, "DashboardFrame should construct cleanly with active session");
    }
}
