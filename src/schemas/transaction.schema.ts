import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type TransactionDocument = Transaction & Document;

@Schema()
export class Transaction {
  @Prop()
  Time: string;

  @Prop()
  Date: string;

  @Prop()
  Sender_account: number;

  @Prop()
  Receiver_account: number;

  @Prop()
  Amount: number;

  @Prop()
  Payment_currency: string;

  @Prop()
  Received_currency: string;

  @Prop()
  Sender_bank_location: string;

  @Prop()
  Receiver_bank_location: string;

  @Prop()
  Payment_type: string;

  @Prop()
  Transaction_ID: string;

  @Prop({ type: Number })
  Is_laundering: number;

  @Prop()
  Laundering_type: string;
}

export const TransactionSchema = SchemaFactory.createForClass(Transaction);
