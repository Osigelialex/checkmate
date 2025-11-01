import { Router } from "express";
import { AuthController } from "../../controllers/auth.controller";
import { authMiddleware } from "../../middlewares/auth.middleware";
import { SignupDTO, VerifyOtpDTO, LoginDTO, RefreshTokenDTO, RequestPasswordResetDTO, ValidatePasswordResetDTO, ResetPasswordDTO } from "../../dtos/auth.dto";
import { validateDto } from "../../middlewares/validation.middleware";

const router = Router();
const authController = new AuthController();

router.post('/signup', validateDto(SignupDTO), authController.signUp);
router.post('/verifyOTP', validateDto(VerifyOtpDTO), authController.verifyOTP);
router.post('/login', validateDto(LoginDTO), authController.login);
router.post('/forgot-password', validateDto(RequestPasswordResetDTO), authController.requestPasswordReset);
router.post('/validate-password-reset', validateDto(ValidatePasswordResetDTO), authController.validatePasswordReset),
router.post('/reset-password', validateDto(ResetPasswordDTO), authController.resetPassword);
router.post('/refresh', validateDto(RefreshTokenDTO), authController.refreshToken);
router.post('/logout', validateDto(RefreshTokenDTO), authMiddleware, authController.logout);

export default router;