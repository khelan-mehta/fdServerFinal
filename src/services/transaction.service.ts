import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  Transaction,
  TransactionDocument,
} from '../schemas/transaction.schema';
import { User } from 'src/schemas/user.schema';

@Injectable()
export class TransactionService {
  constructor(
    @InjectModel(Transaction.name)
    private transactionModel: Model<TransactionDocument>,
    @InjectModel('User') private readonly userModel: Model<User>,
  ) {}

  // Fetch transactions with sorting & pagination
  async getTransactions(page: number, limit: number) {
    const transactions = await this.transactionModel
      .find()
      .sort({ Date: -1, Time: -1 }) // Sorting by latest transactions
      .skip((page - 1) * limit)
      .limit(limit)
      .exec();

    const total = await this.transactionModel.countDocuments();

    return { transactions, total };
  }

  // Fetch transactions where the user is the sender
  async getTransactionsBySender(bankAccount: number) {
    return this.transactionModel.find({ Sender_account: bankAccount }).exec();
  }

  // Fetch transactions where the user is the receiver
  async getTransactionsByReceiver(bankAccount: number) {
    return this.transactionModel.find({ Receiver_account: bankAccount }).exec();
  }

  // Create a new transaction
  async createTransaction(transactionData: any) {
    console.log(transactionData);

    const { Sender_account, Receiver_account, Amount } = transactionData;

    // Find sender and receiver
    console.log('Sender_account Type:', typeof Sender_account, Sender_account);
    console.log(
      'Receiver_account Type:',
      typeof Receiver_account,
      Receiver_account,
    );
    console.log('Amount Type:', typeof Amount, Amount);

    // Convert to Number (Mongoose does not support Long directly)
    const senderBankAcc = Sender_account;
    const receiverBankAcc = Receiver_account;

    console.log(
      'Converted Sender_account Type:',
      typeof senderBankAcc,
      senderBankAcc,
    );
    console.log(
      'Converted Receiver_account Type:',
      typeof receiverBankAcc,
      receiverBankAcc,
    );

    // Find sender and receiver
    const sender = await this.userModel.findOne({
      bankAccount: senderBankAcc, // Use Number
    });

    const receiver = await this.userModel.findOne({
      bankAccount: receiverBankAcc, // Use Number
    });

    if (!sender) {
      console.error('❌ Sender not found:', senderBankAcc);
    }
    if (!receiver) {
      console.error('❌ Receiver not found:', receiverBankAcc);
    }

    if (!sender) {
      throw new Error('Sender account not found.');
    }
    if (!receiver) {
      throw new Error('Receiver account not found.');
    }

    // Check sender balance
    if (sender.balance < Amount) {
      throw new Error('Insufficient balance.');
    }

    // Modify balances
    sender.balance -= Amount;
    receiver.balance += Amount;

    // Save updated balances
    await sender.save();
    await receiver.save();

    // Create and save transaction
    const newTransaction = new this.transactionModel({
      ...transactionData,
    });

    console.log(newTransaction);

    return newTransaction.save();
  }

  // Get only transactions flagged as laundering
  async getLaunderingTransactions() {
    return await this.transactionModel.find({ Is_laundering: 1 }).exec();
  }

  // Categorize transactions based on Laundering_type
  async categorizeLaunderingTransactions() {
    const launderingTransactions = await this.getLaunderingTransactions();
    //console.log(launderingTransactions);

    const categories = launderingTransactions.reduce((acc, txn) => {
      const category = txn.Laundering_type;
      if (!acc[category]) {
        acc[category] = [];
      }
      acc[category].push(txn);
      return acc;
    }, {});

    return categories;
  }

  async searchTransactions(filters: any) {
    const query: any = {};

    if (filters.transactionId) {
      query.Transaction_ID = filters.transactionId;
    }

    if (filters.date) query.Date = filters.date;
    if (filters.senderAccount) query.Sender_account = filters.senderAccount;
    if (filters.receiverAccount)
      query.Receiver_account = filters.receiverAccount;
    if (filters.amountMin) query.Amount = { $gte: filters.amountMin };
    if (filters.amountMax)
      query.Amount = { ...query.Amount, $lte: filters.amountMax };
    if (filters.paymentType) query.Payment_type = filters.paymentType;
    if (filters.isLaundering !== undefined)
      query.Is_laundering = filters.isLaundering;

    const transactions = await this.transactionModel.find(query).exec();

    // If transactionId is provided but doesn't match filters, still include it in the response
    if (filters.transactionId) {
      const transactionById = await this.transactionModel
        .findOne({ Transaction_ID: filters.transactionId })
        .exec();
      if (
        transactionById &&
        !transactions.some((t) => t.Transaction_ID === filters.transactionId)
      ) {
        transactions.push(transactionById);
      }
    }

    return transactions;
  }

  async getFlaggedUsers() {
    const launderingTransactions = await this.getLaunderingTransactions();

    const userMap = new Map<number, TransactionDocument[]>();

    launderingTransactions.forEach((txn) => {
      if (!userMap.has(txn.Sender_account)) {
        userMap.set(txn.Sender_account, []);
      }
      userMap.get(txn.Sender_account)?.push(txn);
    });

    return Array.from(userMap.entries()).map(([user, transactions]) => ({
      user,
      transactions,
      riskLevel: this.calculateRiskLevel(transactions.length),
    }));
  }

  private calculateRiskLevel(count: number) {
    if (count > 5) return 'High';
    if (count > 2) return 'Medium';
    return 'Low';
  }
}
