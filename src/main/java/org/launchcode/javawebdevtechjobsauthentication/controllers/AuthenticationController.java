package org.launchcode.javawebdevtechjobsauthentication.controllers;

import org.launchcode.javawebdevtechjobsauthentication.models.User;
import org.launchcode.javawebdevtechjobsauthentication.models.data.UserRepository;
import org.launchcode.javawebdevtechjobsauthentication.models.dto.LoginFormDTO;
import org.launchcode.javawebdevtechjobsauthentication.models.dto.RegisterFormDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.util.Objects;
import java.util.Optional;

@Controller
public class AuthenticationController {

    @Autowired
    private UserRepository userRepository;

    private static final String sessionKey = "user";

    public User prettyName(HttpSession session) {
        Integer userId = (Integer) session.getAttribute(sessionKey);

        if (userId.equals(null)) {
            return null;
        }
        Optional<User> user = userRepository.findById(userId);

        if (user.isEmpty()) {
            return null;
        }
        return user.get();
    }

    private static void setUser(HttpSession session, User user) {
        session.setAttribute(sessionKey, user.getId());
    }

    @GetMapping("/register")
    public String registerForm(Model model) {
        model.addAttribute("title", "Register Form");
        model.addAttribute(new RegisterFormDTO());
        return "register";
    }

    @PostMapping("/register")
    public String processRegisterForm(@ModelAttribute @Valid RegisterFormDTO registerFormDTO, Errors errors, Model model,
                                      HttpServletRequest request) {

        if (errors.hasErrors()) {
            model.addAttribute("title", "Registration Failed!!!");
            return "/register";
        }

        if (userRepository.findByUsername(registerFormDTO.getUsername()) != null) {
            errors.reject("username already exists.");
            return "/register";
        }

        if (!Objects.equals(registerFormDTO.getPassword(), registerFormDTO.getVerifyPassword())) {
            errors.reject("passwords do not match.");
            return "register";
        }

        User newUser = new User(registerFormDTO.getUsername(), registerFormDTO.getPassword());
        userRepository.save(newUser);
        setUser(request.getSession(), newUser);

        return "redirect:";
    }

    @GetMapping("login")
    public String loginForm(Model model) {
        model.addAttribute("title", "Login");
        model.addAttribute(new LoginFormDTO());
        return "login";
    }

    @PostMapping("login")
    public String processLoginForm(@ModelAttribute @Valid LoginFormDTO loginFormDTO, Errors errors, Model model) {
        User theUser = userRepository.findByUsername(loginFormDTO.getUsername());

        if (errors.hasErrors()) {
            model.addAttribute("title", "Log In");
            return "login";
        }

        if (theUser == null) {
            errors.reject("Invalid user", "User does not exist.");
            return "login";
        }

        if (!theUser.checkPassword(loginFormDTO.getPassword())) {
            errors.reject("Invalid password", "Password is incorrect.");
            return "login";
        }
        
        userRepository.save(theUser);
        return "redirect:";
    }


    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        request.getSession().invalidate();
        return "redirect:/login";
    }
}
