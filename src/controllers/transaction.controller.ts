import { Controller, Get, Post, Query, Body, HttpException, HttpStatus } from '@nestjs/common';
import { TransactionService } from '../services/transaction.service';

@Controller('transactions')
export class TransactionController {
  constructor(private readonly transactionService: TransactionService) {}

  // Fetch paginated transactions
  @Get()
  async getTransactions(
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 10,
  ) {
    return this.transactionService.getTransactions(Number(page), Number(limit));
  }

  // Fetch laundering transactions
  @Get('laundering')
  async getLaunderingTransactions() {
    return this.transactionService.getLaunderingTransactions();
  }

  // Categorize laundering transactions
  @Get('laundering/categories')
  async getCategorizedLaunderingTransactions() {
    return this.transactionService.categorizeLaunderingTransactions();
  }

  @Get('flagged-users')
  async getFlaggedUsers() {
    return this.transactionService.getFlaggedUsers();
  }

  // Search transactions with filters
  @Get('search')
  async searchTransactions(
    @Query('transactionId') transactionId?: string,
    @Query('date') date?: string,
    @Query('senderAccount') senderAccount?: number,
    @Query('receiverAccount') receiverAccount?: number,
    @Query('amountMin') amountMin?: number,
    @Query('amountMax') amountMax?: number,
    @Query('paymentType') paymentType?: string,
    @Query('isLaundering') isLaundering?: number,
  ) {
    return this.transactionService.searchTransactions({
      transactionId,
      date,
      senderAccount: Number(senderAccount),
      receiverAccount: Number(receiverAccount),
      amountMin: Number(amountMin),
      amountMax: Number(amountMax),
      paymentType,
      isLaundering: Number(isLaundering),
    });
  }

  // Fetch transactions for a given bank account (sent and received)
  @Get('user')
  async getUserTransactions(@Query('bankAccount') bankAccount: number) {
    if (!bankAccount) {
      throw new HttpException('bankAccount is required', HttpStatus.BAD_REQUEST);
    }

    const sentTransactions = await this.transactionService.getTransactionsBySender(
      Number(bankAccount),
    );
    const receivedTransactions = await this.transactionService.getTransactionsByReceiver(
      Number(bankAccount),
    );

    return {
      sentTransactions,
      receivedTransactions,
    };
  }

  // Create a new transaction
  @Post()
  async createTransaction(@Body() transactionData: any) {
    const requiredFields = [
      'Time',
      'Date',
      'Sender_account',
      'Receiver_account',
      'Amount',
      'Payment_currency',
      'Received_currency',
      'Sender_bank_location',
      'Receiver_bank_location',
      'Payment_type',
      'Transaction_ID',
    ];

    // Validate required fields
    for (const field of requiredFields) {
      if (!transactionData[field]) {
        throw new HttpException(
          `${field} is required`,
          HttpStatus.BAD_REQUEST,
        );
      }
    }

    // Create the transaction
    return this.transactionService.createTransaction(transactionData);
  }
}