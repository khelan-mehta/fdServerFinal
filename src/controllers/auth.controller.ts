import {
  Controller,
  Post,
  Body,
  UseGuards,
  Req,
  Get,
  UnauthorizedException,
  HttpException,
  HttpStatus,
  Res,
  Param,
  Query,
  NotFoundException,
  Put,
} from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { GoogleAuthGuard } from '../guards/google-auth.guard';
import { SendOtpDto } from 'src/dtos/sendOtps.dto';
import { ResetPasswordDto, VerifyOtpDto } from 'src/dtos/verifyOtp.dto';
import aws from 'aws-sdk';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { Response } from 'express';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/services/user.service';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';

const s3 = new S3Client({
  region: 'eu-north-1',
  credentials: {
    accessKeyId: 'AKIAVVANBAJNCJ3LVIJC',
    secretAccessKey: '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',
  },
});

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
  ) {}

  @Get('image')
  async getImage(@Query('url') url: string, @Res() res) {
    const response = await axios.get(url, { responseType: 'arraybuffer' });
    res.setHeader('Content-Type', response.headers['content-type']);
    res.send(response.data);
  }

  @Post('login')
  async login(
    @Body() loginDto: { email: string; password: string; deviceId: string },
  ) {
    const user = await this.authService.validateUser(
      loginDto.email,
      loginDto.password,
      loginDto.deviceId,
    );

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    console.log(loginDto.deviceId);

    // If deviceId is not in the stored list, trigger OTP verification
    if (!user.deviceId.includes(loginDto.deviceId)) {
      console.log('hit');

      const otpSession = await this.authService.createOtpSession(user);
      await this.authService.sendOtpEmail(user.email, otpSession.otp);

      return {
        message: 'OTP sent to email. Verify to complete login.',
        loggedIn: false,
      };
    }

    return this.authService.login(user);
  }

  @Post('verify-otp-device')
  async verifyOtpDeviceId(
    @Body() verifyOtpDto: { email: string; otp: string; deviceId: string },
  ) {
    const valid = await this.authService.verifyOtp(
      verifyOtpDto.email,
      verifyOtpDto.otp,
    );

    if (!valid) {
      throw new UnauthorizedException('Invalid OTP');
    }

    const user = await this.authService.findUserByEmail(verifyOtpDto.email);

    // Store the new deviceId in the user's record
    if (!user.deviceId.includes(verifyOtpDto.deviceId)) {
      user.deviceId.push(verifyOtpDto.deviceId);
      await user.save(); // Assuming a Mongoose model
    }

    return this.authService.login(user);
  }

  @Post('add-device')
  async addDevice(@Body() addDeviceDto: { email: string; deviceId: string }) {
    const user = await this.authService.findUserByEmail(addDeviceDto.email);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.deviceId.includes(addDeviceDto.deviceId)) {
      user.deviceId.push(addDeviceDto.deviceId);
      await user.save();
    }

    return { message: 'Device added successfully' };
  }

  @Post('register')
  async register(
    @Body()
    registerDto: {
      email: string;
      password: string;
      username: string;
      bankAccount: string;
      deviceId: string; // Include deviceId in the registration request
    },
  ) {
    try {
      const response = await this.authService.register(
        registerDto.email,
        registerDto.password,
        registerDto.username,
        registerDto.bankAccount,
        registerDto.deviceId, // Pass deviceId to the service
      );
      return response; // Returning accessToken and userId
    } catch (error) {
      return { message: error.message };
    }
  }

  @Get('google/login')
  @UseGuards(GoogleAuthGuard)
  async googleLogin() {
    return { message: 'Redirecting to Google' };
  }

  @Get('google/redirect')
  @UseGuards(GoogleAuthGuard)
  async googleLoginCallback(@Req() req, @Res() res: Response) {
    const googleUser = req.user; // This will contain Google profile info
    const redirectBaseUrl = process.env.HOME_URL_2;

    // Try to find an existing user by email
    let user = await this.authService.findUserByEmail(googleUser.email);

    if (user) {
      // Link Google login info to the existing account
      await this.authService.linkGoogleAccount(user, googleUser);

      // Check if the user has a username, implying they are registered
      if (user.username) {
        user.isRegistered = true; // Set isRegistered to true if the user has a username
        await user.save(); // Save the updated user
      }
    } else {
      // Check if the user is not registered before creating a new account
      if (!googleUser.isRegistered) {
        // Redirect with a message query parameter
        return res.redirect(
          `${redirectBaseUrl}/register?message=kindly%20register%20first&email=${googleUser.email}`,
        );
      }

      // Create a new user with Google info if the user is registered
      user = await this.authService.createUserWithGoogle(googleUser);
    }

    // Generate an access token for the user
    const accessToken = await this.authService.generateAccessToken(user);

    // Save the access token in the database
    await this.authService.saveAccessToken(user.id, accessToken);

    // Ensure deviceId is an array, even if empty
    const deviceIdArray = Array.isArray(user.deviceId) ? user.deviceId : [];

    // Encode the deviceId array as a JSON string
    const encodedDeviceIds = encodeURIComponent(JSON.stringify(deviceIdArray));

    // Redirect to the appropriate page with the access token, user ID, and deviceId array
    const redirectUrl = `${redirectBaseUrl}/dashboard?access_token=${accessToken}&userId=${user.id}&deviceIds=${encodedDeviceIds}`;

    return res.redirect(redirectUrl);
  }

  @Get('protected')
  @UseGuards(JwtAuthGuard)
  getProtectedResource() {
    return { message: 'This is a protected route' };
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  async getUserInfo(@Param('id') userId: string, @Res() res: Response) {
    // The controller logic for fetching user info
    try {
      const user = await this.userService.getUserById(userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      // If needed, you can perform additional logic here before sending the response
      // Send the user data and the new access token in the response
      return res.status(200).json({
        message: 'User info retrieved successfully.',
        user,
        newAccessToken: user.accessToken, // Retrieve from response locals
      });
    } catch (error) {
      return res.status(500).json({ message: error.message });
    }
  }

  @Post('forgot-password')
  async forgotPassword(@Body() sendOtpDto: SendOtpDto) {
    const user = await this.authService.findUserByEmail(sendOtpDto.email);
    if (!user) {
      throw new HttpException('Email not found', HttpStatus.NOT_FOUND);
    }

    const otpSession = await this.authService.createOtpSession(user);
    // Send OTP to user's email
    await this.authService.sendOtpEmail(user.email, otpSession.otp);

    return { message: 'OTP sent to email' };
  }

  // Endpoint to verify OTP
  @Post('verify-otp')
  async verifyOtp(@Body() verifyOtpDto: VerifyOtpDto) {
    const valid = await this.authService.verifyOtp(
      verifyOtpDto.email,
      verifyOtpDto.otp,
    );
    if (!valid) {
      throw new HttpException('Invalid OTP', HttpStatus.FORBIDDEN);
    }

    return { message: 'OTP verified successfully' };
  }

  @Put('kyc')
  async updateKycStatus(@Body('userId') userId: string) {
    const updatedUser = await this.authService.updateKycStatus(userId);

    if (!updatedUser) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    return { message: 'KYC status updated successfully', user: updatedUser };
  }

  @Get('fetch-url/fetch')
  async generateUploadURL() {
    const bucketName = 'direct-upload-s3-khelan';
    const randomFileName = `image-${uuidv4()}.png`;
    const command = new PutObjectCommand({
      Bucket: bucketName,
      Key: randomFileName,
    });

    const uploadURL = await getSignedUrl(s3, command, { expiresIn: 60 });
    return { uploadURL };
  }

  // Endpoint for password reset
  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    const resetSuccess = await this.authService.resetPassword(
      resetPasswordDto.email,
      resetPasswordDto.newPassword,
    );

    if (!resetSuccess) {
      throw new HttpException('Password reset failed', HttpStatus.BAD_REQUEST);
    }

    return { message: 'Password reset successful' };
  }
}
